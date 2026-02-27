import logging
from dataclasses import dataclass
from ingestion.extractor import Route

logger = logging.getLogger('aart')

# ─────────────────────────────────────────────
# Data
# ─────────────────────────────────────────────

@dataclass
class SymbolicFinding:
    rule: str
    confidence: float       # 0.0 - 1.0
    route: Route
    evidence: str
    plain_english: str

# DB calls that READ data — IDOR candidates
READ_CALLS = {
    'findById', 'findOne', 'findByIdAndDelete',
    'find', 'findAll', 'get'
}

# DB calls that WRITE data — horizontal escalation candidates
WRITE_CALLS = {
    'findByIdAndUpdate', 'findOneAndUpdate',
    'updateOne', 'updateMany', 'update',
    'save', 'create', 'insertOne'
}

ALL_DB_CALLS = READ_CALLS | WRITE_CALLS

ELEVATED_MW = {'isadmin', 'admin', 'requireadmin', 'superuser', 'isstaff'}

# ─────────────────────────────────────────────
# AST helper — generic node walker
# ─────────────────────────────────────────────

def _walk_ast(node, visitor):
    """
    Recursively walk every node in an esprima AST.
    Calls visitor(node) on each node.
    visitor can return 'stop' to skip a node's children.
    """
    if node is None or not hasattr(node, '__dict__'):
        return

    result = visitor(node)
    if result == 'stop':
        return

    for key, value in node.__dict__.items():
        if isinstance(value, list):
            for item in value:
                _walk_ast(item, visitor)
        elif hasattr(value, '__dict__'):
            _walk_ast(value, visitor)

# ─────────────────────────────────────────────
# Taint Tracker
# ─────────────────────────────────────────────

class TaintTracker:
    """
    Walks a handler body AST and tracks which variables
    hold user-controlled (tainted) values.

    Taint sources:
        req.params.x  req.body.x  req.query.x

    Taint propagates through assignments:
        const id = req.params.id   →  'id' is tainted
        const copy = id            →  'copy' is tainted
    """

    def __init__(self):
        # Set of variable names known to hold tainted values
        self.tainted: set[str] = set()

    def _is_tainted_member(self, node) -> bool:
        """
        Returns True if a MemberExpression node represents
        req.params.x, req.body.x, or req.query.x
        """
        if getattr(node, 'type', None) != 'MemberExpression':
            return False

        obj = node.object
        # obj should itself be a MemberExpression: req.params / req.body / req.query
        if getattr(obj, 'type', None) != 'MemberExpression':
            return False

        root = getattr(obj.object, 'name', '')
        prop = getattr(obj.property, 'name', '')

        return root == 'req' and prop in ('params', 'body', 'query')

    def _node_is_tainted(self, node) -> bool:
        if node is None:
            return False

        node_type = getattr(node, 'type', None)

        # Direct taint source: req.params.id passed straight into a call
        if node_type == 'MemberExpression' and self._is_tainted_member(node):
            return True

        # Tainted variable reference
        if node_type == 'Identifier' and getattr(node, 'name', '') in self.tainted:
            return True

        # Unwrap await
        if node_type == 'AwaitExpression':
            return self._node_is_tainted(node.argument)

        # Unwrap assignment expressions: (x = req.params.id)
        if node_type == 'AssignmentExpression':
            return self._node_is_tainted(node.right)

        return False

    def seed(self, body_ast):
        """
        Pass 1: Find all variable declarations where the
        right-hand side is a taint source.

        Handles:
            const id = req.params.id
            const data = req.body
            let q = req.query.search
        """
        def visitor(node):
            if getattr(node, 'type', None) == 'VariableDeclaration':
                for declarator in (node.declarations or []):
                    if getattr(declarator, 'type', None) == 'VariableDeclarator':
                        var_name = getattr(declarator.id, 'name', None)
                        init = declarator.init
                        if var_name and init:
                            # Unwrap await if present: const x = await something
                            if getattr(init, 'type', None) == 'AwaitExpression':
                                init = init.argument
                            if self._is_tainted_member(init):
                                self.tainted.add(var_name)
                                logger.debug(f"    [taint] seeded: '{var_name}'")

        _walk_ast(body_ast, visitor)

    def propagate(self, body_ast):
        """
        Pass 2: Find assignments where a tainted variable
        is assigned to a new variable.

        Handles:
            const invoiceId = id      (id already tainted)
            let copy = taintedVar
        """
        changed = True
        # Loop until no new variables are tainted — handles chains
        while changed:
            changed = False

            def visitor(node):
                nonlocal changed
                if getattr(node, 'type', None) == 'VariableDeclarator':
                    var_name = getattr(node.id, 'name', None)
                    if var_name and var_name not in self.tainted:
                        if node.init and self._node_is_tainted(node.init):
                            self.tainted.add(var_name)
                            logger.debug(f"    [taint] propagated: '{var_name}'")
                            changed = True

            _walk_ast(body_ast, visitor)

    def run(self, body_ast):
        """Seed then propagate — call this once before querying."""
        self.seed(body_ast)
        self.propagate(body_ast)

# ─────────────────────────────────────────────
# Sink detection
# ─────────────────────────────────────────────

def _find_tainted_db_calls(body_ast, tracker: TaintTracker) -> list[dict]:
    """
    Walk the AST looking for DB method calls where at least
    one argument is tainted.

    Returns a list of dicts:
        { 'call': 'findById', 'type': 'read'|'write', 'arg_names': [...] }
    """
    hits = []

    def visitor(node):
        # Looking for: Something.findById(taintedArg)
        if getattr(node, 'type', None) == 'CallExpression':
            callee = node.callee
            if getattr(callee, 'type', None) == 'MemberExpression':
                method_name = getattr(callee.property, 'name', '')
                if method_name in ALL_DB_CALLS:
                    # Check if any argument is tainted
                    tainted_args = []
                    for arg in (node.arguments or []):
                        if tracker._node_is_tainted(arg) or tracker._is_tainted_member(arg):
                            # Get a readable name for the arg
                            if getattr(arg, 'type', '') == 'Identifier':
                                arg_name = arg.name
                            elif getattr(arg, 'type', '') == 'MemberExpression':
                                # Build req.params.id style string
                                parts = []
                                n = arg
                                while getattr(n, 'type', '') == 'MemberExpression':
                                    parts.append(getattr(n.property, 'name', '?'))
                                    n = n.object
                                parts.append(getattr(n, 'name', '?'))
                                arg_name = '.'.join(reversed(parts))
                            else:
                                arg_name = getattr(arg, 'type', 'unknown')
                            tainted_args.append(arg_name)

                    if tainted_args:
                        call_type = 'read' if method_name in READ_CALLS else 'write'
                        hits.append({
                            'call': method_name,
                            'type': call_type,
                            'arg_names': tainted_args
                        })
                        logger.debug(f"    [sink] tainted DB call: {method_name}({tainted_args})")

    _walk_ast(body_ast, visitor)
    return hits


def _has_valid_ownership_check(body_ast, tracker: TaintTracker) -> bool:
    """
    Walk the AST looking for an ownership check. Detects two patterns:

    Pattern A — tainted variable compared to req.user.id:
        req.params.id === req.user.id
        userId === req.user.id

    Pattern B — DB result's _id compared to req.user.id:
        user._id.toString() !== req.user.id
        doc._id === req.user.id

    Either pattern is sufficient to clear an IDOR finding.
    """
    found = [False]

    def _is_req_user_id(node) -> bool:
        """Check if node is req.user.id or req.user._id"""
        if getattr(node, 'type', None) != 'MemberExpression':
            return False
        prop = getattr(node.property, 'name', '')
        if prop not in ('id', '_id'):
            return False
        obj = node.object
        if getattr(obj, 'type', None) != 'MemberExpression':
            return False
        return (getattr(obj.object, 'name', '') == 'req' and
                getattr(obj.property, 'name', '') == 'user')

    def _is_id_field_access(node) -> bool:
        """
        Check if node accesses a ._id or .id field on anything.
        Handles:
            someVar._id
            someVar._id.toString()   (CallExpression wrapping the above)
        """
        # Unwrap .toString() call: someVar._id.toString()
        if getattr(node, 'type', None) == 'CallExpression':
            callee = node.callee
            if getattr(callee, 'type', None) == 'MemberExpression':
                # callee.object should be the ._id access
                return _is_id_field_access(callee.object)

        # Direct field access: someVar._id or someVar.id
        if getattr(node, 'type', None) == 'MemberExpression':
            prop = getattr(node.property, 'name', '')
            return prop in ('_id', 'id')

        return False

    def _expr_involves_taint_or_id(node) -> bool:
        """
        Returns True if node is:
        - A tainted variable
        - A direct req.params/body/query access
        - A ._id field access on any variable (DB result pattern)
        """
        # Pattern A: tainted variable or direct req.params access
        if tracker._node_is_tainted(node) or tracker._is_tainted_member(node):
            return True

        # Pattern B: someVar._id or someVar._id.toString()
        if _is_id_field_access(node):
            return True

        return False

    def visitor(node):
        if found[0]:
            return 'stop'

        if getattr(node, 'type', None) == 'BinaryExpression':
            op = getattr(node, 'operator', '')
            if op in ('===', '!==', '==', '!='):
                left = node.left
                right = node.right
                # left involves taint/id AND right is req.user.id
                # OR right involves taint/id AND left is req.user.id
                if ((_expr_involves_taint_or_id(left) and _is_req_user_id(right)) or
                        (_is_req_user_id(left) and _expr_involves_taint_or_id(right))):
                    found[0] = True
                    logger.debug(f"    [check] ownership check found")

    _walk_ast(body_ast, visitor)
    return found[0]

    def _is_req_user_id(node) -> bool:
        """Check if node is req.user.id or req.user._id"""
        if getattr(node, 'type', None) != 'MemberExpression':
            return False
        obj = node.object
        prop = getattr(node.property, 'name', '')
        if prop not in ('id', '_id'):
            return False
        # obj should be req.user
        if getattr(obj, 'type', None) != 'MemberExpression':
            return False
        root = getattr(obj.object, 'name', '')
        mid = getattr(obj.property, 'name', '')
        return root == 'req' and mid == 'user'

    def _expr_involves_taint(node) -> bool:
        """Check if a node is or contains a tainted variable."""
        if tracker._node_is_tainted(node):
            return True
        # Also handle: taintedVar.toString()
        if (getattr(node, 'type', None) == 'CallExpression' and
                getattr(node.callee, 'type', None) == 'MemberExpression'):
            return tracker._node_is_tainted(node.callee.object)
        return False

    def visitor(node):
        if found[0]:
            return 'stop'

        if getattr(node, 'type', None) == 'BinaryExpression':
            op = getattr(node, 'operator', '')
            if op in ('===', '!==', '==', '!='):
                left = node.left
                right = node.right
                # Pattern: tainted === req.user.id  OR  req.user.id === tainted
                if ((_expr_involves_taint(left) and _is_req_user_id(right)) or
                        (_is_req_user_id(left) and _expr_involves_taint(right))):
                    found[0] = True
                    logger.debug(f"    [check] ownership check found")

    _walk_ast(body_ast, visitor)
    return found[0]


def _has_self_id_check(body_ast, tracker: TaintTracker) -> bool:
    """
    For horizontal escalation: check if the tainted ID param
    is compared against req.user.id anywhere — meaning the
    user is only allowed to modify their own record.

        req.params.id === req.user.id
        userId === req.user.id

    This is the same as ownership check but specifically
    relevant to write operations.
    """
    return _has_valid_ownership_check(body_ast, tracker)

# ─────────────────────────────────────────────
# Per-route analysis
# ─────────────────────────────────────────────

def analyze_route(route: Route) -> list[SymbolicFinding]:
    """
    Run full AST-based symbolic analysis on a single route.
    Returns a list of SymbolicFindings (may be empty).
    """
    findings = []

    # Skip named handlers — no AST to analyze
    if route.handler_ast is None:
        logger.debug(f"  Skipping {route.method} {route.path} — named handler, no AST")
        return findings

    is_elevated = any(m.lower() in ELEVATED_MW for m in route.middleware)

    logger.debug(f"  Analyzing {route.method} {route.path}")

    # ── Step 1: Run taint tracker ──
    tracker = TaintTracker()
    tracker.run(route.handler_ast)

    # Note: taint set may be empty if req.params flows directly into
    # a DB call without intermediate assignment — we still check sinks
    logger.debug(f"    Taint set: {tracker.tainted}")

    logger.debug(f"    Taint set: {tracker.tainted}")

    # ── Step 2: Find tainted DB call sinks ──
    tainted_calls = _find_tainted_db_calls(route.handler_ast, tracker)
    logger.debug(f"    Tainted calls: {tainted_calls}")

    if not tainted_calls:
        logger.debug(f"    No tainted DB calls found")
        return findings

    # ── Step 3: Check for ownership validation ──
    has_ownership = _has_valid_ownership_check(route.handler_ast, tracker)

    # Separate read vs write calls
    read_calls  = [c for c in tainted_calls if c['type'] == 'read']
    write_calls = [c for c in tainted_calls if c['type'] == 'write']

    # ── Rule 1: IDOR — tainted read with no ownership check ──
    if read_calls and not has_ownership and not is_elevated and ':' in route.path:
        call_names = [c['call'] for c in read_calls]
        findings.append(SymbolicFinding(
            rule="TAINT_NO_OWNERSHIP_CHECK",
            confidence=0.90 if route.method == 'GET' else 0.80,
            route=route,
            evidence=(
                f"Tainted variable(s) {tracker.tainted} flow into "
                f"{call_names} with no ownership comparison against req.user.id."
            ),
            plain_english=(
                f"{route.method} {route.path} reads user-supplied input directly into a "
                f"database query without verifying the record belongs to the requesting user. "
                f"An attacker can read any user's data by changing the ID in the URL."
            )
        ))

    # ── Rule 2: Horizontal privilege escalation ──
    # Tainted ID flows into a WRITE call, no self-check, not admin-only
    if write_calls and not has_ownership and not is_elevated and ':' in route.path:
        call_names = [c['call'] for c in write_calls]
        findings.append(SymbolicFinding(
            rule="HORIZONTAL_PRIVILEGE_ESCALATION",
            confidence=0.85,
            route=route,
            evidence=(
                f"Tainted variable(s) {tracker.tainted} flow into "
                f"write call(s) {call_names} with no check that the "
                f"target ID matches req.user.id."
            ),
            plain_english=(
                f"{route.method} {route.path} allows a logged-in user to modify "
                f"another user's record by changing the ID in the URL. "
                f"There is no check that req.params.id belongs to the requesting user."
            )
        ))

    # ── Rule 3: Mass assignment ──
    # req.body passed wholesale into a create/update call
    def _has_mass_assignment(body_ast) -> bool:
        found = [False]

        def visitor(node):
            if found[0]:
                return 'stop'
            if getattr(node, 'type', None) == 'CallExpression':
                callee = node.callee
                method = getattr(getattr(callee, 'property', None), 'name', '')
                if method in WRITE_CALLS | {'create'}:
                    for arg in (node.arguments or []):
                        # Direct req.body as argument
                        if (getattr(arg, 'type', None) == 'MemberExpression' and
                                getattr(arg.object, 'name', '') == 'req' and
                                getattr(arg.property, 'name', '') == 'body'):
                            found[0] = True
                        # Tainted variable that originated from req.body
                        if (getattr(arg, 'type', None) == 'Identifier' and
                                arg.name in tracker.tainted):
                            # Check if it was seeded from req.body specifically
                            found[0] = True

        _walk_ast(body_ast, visitor)
        return found[0]

    if _has_mass_assignment(route.handler_ast):
        findings.append(SymbolicFinding(
            rule="MASS_ASSIGNMENT",
            confidence=0.80,
            route=route,
            evidence="req.body passed directly into a DB write call with no field filtering.",
            plain_english=(
                f"{route.method} {route.path} passes the entire request body directly into a "
                f"database write. An attacker can set fields they shouldn't control, "
                f"like 'isAdmin' or 'role'."
            )
        ))

    return findings

# ─────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────

def run_symbolic_engine(routes: list[Route], sources: dict[str, str]) -> list[SymbolicFinding]:
    """
    Run symbolic analysis across all routes.
    sources dict is kept in the signature for API compatibility
    but is no longer used — analysis is now AST-based.
    """
    all_findings = []
    for route in routes:
        findings = analyze_route(route)
        all_findings.extend(findings)
    return all_findings