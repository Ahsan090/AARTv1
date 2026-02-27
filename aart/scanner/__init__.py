from dataclasses import dataclass
from ingestion.extractor import Route

@dataclass
class Finding:
    rule: str
    severity: str          # CRITICAL / HIGH / MEDIUM / INFO
    route: Route
    description: str
    plain_english: str

# Middleware names that suggest ownership/auth checks
AUTH_MIDDLEWARE = {'authmiddleware', 'authenticate', 'auth', 'verifyjwt', 'requireauth', 'isloggedin'}
OWNERSHIP_MIDDLEWARE = {'isowner', 'checkowner', 'verifyowner', 'belongstouser', 'owneronly'}
ELEVATED_MIDDLEWARE = {'isadmin', 'admin', 'requireadmin', 'superuser', 'isstaff'}

def _has_auth(route: Route) -> bool:
    return any(m.lower() in AUTH_MIDDLEWARE for m in route.middleware)

def _has_ownership_check(route: Route) -> bool:
    return any(m.lower() in OWNERSHIP_MIDDLEWARE for m in route.middleware)

def _has_dynamic_segment(path: str) -> bool:
    return ':' in path

def _resource_name(path: str) -> str:
    """Extract base resource from path e.g. /invoices/:id -> invoices"""
    parts = [p for p in path.split('/') if p and not p.startswith(':')]
    return parts[0] if parts else path

def run_heuristic_scanner(routes: list[Route]) -> list[Finding]:
    findings = []

    # Rule 1: IDOR candidate
    for route in routes:
        if (route.method == 'GET'
                and _has_dynamic_segment(route.path)
                and _has_auth(route)
                and not _has_ownership_check(route)):
            findings.append(Finding(
                rule="IDOR_CANDIDATE",
                severity="HIGH",
                route=route,
                description=f"GET {route.path} uses a dynamic ID but has no ownership check middleware.",
                plain_english=(
                    f"Any logged-in user can probably read anyone else's "
                    f"{_resource_name(route.path)} just by changing the ID in the URL. "
                    f"There's no middleware verifying the resource belongs to them."
                )
            ))

    # Rule 2: Missing auth entirely
    for route in routes:
        if not route.middleware:
            findings.append(Finding(
                rule="MISSING_AUTH",
                severity="CRITICAL",
                route=route,
                description=f"{route.method} {route.path} has no middleware at all.",
                plain_english=(
                    f"{route.method} {route.path} is completely unprotected — "
                    f"anyone on the internet can call it without logging in."
                )
            ))

    # Rule 3: Privilege inconsistency on same resource
    from collections import defaultdict
    resource_routes = defaultdict(list)
    for route in routes:
        resource_routes[_resource_name(route.path)].append(route)

    for resource, group in resource_routes.items():
        elevated = [r for r in group if any(m.lower() in ELEVATED_MIDDLEWARE for m in r.middleware)]
        non_elevated = [r for r in group if not any(m.lower() in ELEVATED_MIDDLEWARE for m in r.middleware)]
        if elevated and non_elevated:
            for route in non_elevated:
                findings.append(Finding(
                    rule="PRIVILEGE_INCONSISTENCY",
                    severity="MEDIUM",
                    route=route,
                    description=f"Some routes on '{resource}' require elevated privileges but {route.method} {route.path} does not.",
                    plain_english=(
                        f"Other endpoints on '{resource}' require admin-level access, "
                        f"but {route.method} {route.path} doesn't — this asymmetry might be intentional "
                        f"or could be a misconfiguration worth reviewing."
                    )
                ))

    return findings