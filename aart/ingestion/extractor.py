import esprima
from dataclasses import dataclass, field

@dataclass
class Route:
    method: str          # GET, POST, PUT, DELETE
    path: str            # e.g. /invoices/:id
    middleware: list     # e.g. ['authMiddleware', 'isAdmin']
    handler: str         # the final handler function name or 'anonymous'
    source_file: str     # which file it came from
    handler_ast: object = field(default=None)  # AST body node of inline handler (or None if named)

def extract_routes(filepath: str, source: str) -> list[Route]:
    routes = []
    try:
        tree = esprima.parseScript(source, tolerant=True, range=True)
    except Exception:
        return routes

    _walk(tree, source, filepath, routes)
    return routes

def _walk(node, source, filepath, routes):
    if not isinstance(node, esprima.nodes.Script) and not hasattr(node, 'type'):
        return

    if getattr(node, 'type', None) == 'ExpressionStatement':
        expr = node.expression
        if (getattr(expr, 'type', None) == 'CallExpression' and
                getattr(expr.callee, 'type', None) == 'MemberExpression'):

            obj = expr.callee.object
            prop = expr.callee.property

            http_methods = {'get', 'post', 'put', 'delete', 'patch'}
            if getattr(prop, 'name', '').lower() in http_methods:
                args = expr.arguments
                if len(args) >= 2:
                    path_arg = args[0]
                    route_path = path_arg.value if hasattr(path_arg, 'value') else '?'

                    middleware = []
                    for arg in args[1:-1]:
                        if hasattr(arg, 'name'):
                            middleware.append(arg.name)

                    handler_arg = args[-1]

                    # --- NEW: capture handler AST if it's an inline function ---
                    handler_name = 'anonymous'
                    handler_ast = None

                    INLINE_TYPES = {
                        'ArrowFunctionExpression',
                        'FunctionExpression'
                    }

                    if handler_arg.type in INLINE_TYPES:
                        # handler_arg.body is the BlockStatement node
                        # — this is the AST we pass to the symbolic engine
                        handler_ast = handler_arg.body
                        handler_name = 'anonymous'
                    elif hasattr(handler_arg, 'name'):
                        # Named reference like getInvoice — symbolic engine
                        # will skip this for now
                        handler_name = handler_arg.name
                        handler_ast = None
                    # -----------------------------------------------------------

                    routes.append(Route(
                        method=prop.name.upper(),
                        path=route_path,
                        middleware=middleware,
                        handler=handler_name,
                        source_file=filepath,
                        handler_ast=handler_ast
                    ))

    # Recurse into child nodes
    for key in node.__dict__:
        child = getattr(node, key)
        if isinstance(child, list):
            for item in child:
                if hasattr(item, '__dict__'):
                    _walk(item, source, filepath, routes)
        elif hasattr(child, '__dict__'):
            _walk(child, source, filepath, routes)