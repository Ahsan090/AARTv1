import re
from dataclasses import dataclass
from ingestion.extractor import Route

@dataclass
class SymbolicFinding:
    rule: str
    confidence: float       # 0.0 - 1.0
    route: Route
    evidence: str
    plain_english: str

# Patterns that indicate tainted (user-controlled) input being used in a query
TAINTED_SOURCES = [
    r'req\.params\.\w+',
    r'req\.body\.\w+',
    r'req\.query\.\w+',
]

# Patterns that indicate a DB query using a variable
DB_QUERY_PATTERNS = [
    r'\.findById\s*\(',
    r'\.findOne\s*\(',
    r'\.findByIdAndUpdate\s*\(',
    r'\.findByIdAndDelete\s*\(',
    r'\.update\s*\(',
    r'\.where\s*\(',
]

# Patterns that indicate an ownership check
OWNERSHIP_CHECK_PATTERNS = [
    r'req\.user\.id',
    r'req\.user\._id',
    r'userId\s*===',
    r'userId\s*!==',
    r'\.toString\(\)\s*!==\s*req\.user',
    r'\.toString\(\)\s*===\s*req\.user',
    r'403',
    r'Forbidden',
    r'Unauthorized',
]

# Patterns that indicate mass assignment risk
MASS_ASSIGNMENT_PATTERNS = [
    r'\.create\s*\(\s*req\.body\s*\)',
    r'\.update\s*\(.*req\.body',
    r'\.findByIdAndUpdate\s*\(.*req\.body',
    r'Object\.assign\s*\(.*req\.body',
]

def _body_text(route: Route, source: str) -> str:
    """
    Find the handler body for this specific route by matching
    the HTTP method AND path together, e.g. app.post('/users/:id', ...)
    """
    method_lower = route.method.lower()
    path_escaped = re.escape(route.path)

    # Match: app.get('/users/:id'  or  router.post("/users/:id"
    pattern = rf'\.{method_lower}\s*\(\s*[\'\"]{path_escaped}[\'\"]'
    match = re.search(pattern, source)
    if not match:
        return ""

    start = match.start()
    segment = source[start:start + 1200]

    # Find opening brace of handler body
    brace_start = segment.find('{')
    if brace_start == -1:
        return segment[:400]

    # Walk forward counting braces to find matching closing brace
    depth = 0
    for i, ch in enumerate(segment[brace_start:], start=brace_start):
        if ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                return segment[brace_start:i+1]

    return segment[brace_start:]

    # Walk forward counting braces to find the matching closing brace
    depth = 0
    for i, ch in enumerate(segment[brace_start:], start=brace_start):
        if ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                return segment[brace_start:i+1]

    return segment[brace_start:]

def analyze_route(route: Route, source: str) -> list[SymbolicFinding]:
    findings = []
    body = _body_text(route, source)
    if not body:
        return findings

    # Add this temporarily at the top of analyze_route, right after `body = _body_text(route, source)`
    #print(f"\n[DEBUG] {route.method} {route.path}")
    #print(f"[DEBUG] body extract: {repr(body[:300])}")
    

    # ADD THIS BLOCK RIGHT HERE — before any pattern matching
    ELEVATED_MW = {'isadmin', 'admin', 'requireadmin', 'superuser', 'isstaff'}
    is_elevated = any(m.lower() in ELEVATED_MW for m in route.middleware)

    has_tainted_input = any(re.search(p, body, re.DOTALL) for p in TAINTED_SOURCES)
    has_db_query = any(re.search(p, body, re.DOTALL) for p in DB_QUERY_PATTERNS)
    has_ownership_check = any(re.search(p, body, re.DOTALL) for p in OWNERSHIP_CHECK_PATTERNS)
    has_mass_assignment = any(re.search(p, body, re.DOTALL) for p in MASS_ASSIGNMENT_PATTERNS)

    #TEMP
    #print(f"[DEBUG] has_tainted: {has_tainted_input}, has_db: {has_db_query}, has_mass: {has_mass_assignment}")

    # Rule 1: THEN CHANGE THIS LINE to add `and not is_elevated`
    if (has_tainted_input and has_db_query and not has_ownership_check
            and ':' in route.path
            and not is_elevated):   # <-- the new condition
        confidence = 0.85 if route.method == 'GET' else 0.75
        findings.append(SymbolicFinding(
            rule="TAINT_NO_OWNERSHIP_CHECK",
            confidence=confidence,
            route=route,
            evidence=f"User-controlled input (req.params/body) flows into a DB query with no ownership verification detected.",
            plain_english=(
                f"{route.method} {route.path} reads user-supplied input directly into a "
                f"database query without checking that the resulting record belongs to the "
                f"requesting user. An attacker can enumerate other users' records by changing the ID."
            )
        ))

    # Rule 2: Mass assignment
    if has_mass_assignment:
        findings.append(SymbolicFinding(
            rule="MASS_ASSIGNMENT",
            confidence=0.80,
            route=route,
            evidence="req.body passed directly into a create/update DB call with no field filtering.",
            plain_english=(
                f"{route.method} {route.path} passes the entire request body directly into a "
                f"database write. An attacker can set fields they shouldn't control, like 'isAdmin' or 'role'."
            )
        ))

    return findings

def run_symbolic_engine(routes: list[Route], sources: dict[str, str]) -> list[SymbolicFinding]:
    all_findings = []
    for route in routes:
        source = sources.get(route.source_file, "")
        findings = analyze_route(route, source)
        all_findings.extend(findings)
    return all_findings