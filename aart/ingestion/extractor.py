import esprima
from dataclasses import dataclass, field

@dataclass
class Route:
    method: str          # GET, POST, PUT, DELETE
    path: str            # e.g. /invoices/:id
    middleware: list     # e.g. ['authMiddleware', 'isAdmin']
    handler: str         # the final handler function name
    source_file: str     # which file it came from
    raw_handler_body: str = ""  # we'll use this in Phase 4

def extract_routes(filepath: str, source: str) -> list[Route]:
    routes = []
    try:
        tree = esprima.parseScript(source, tolerant=True)
    except Exception:
        return routes  # skip unparseable files gracefully

    _walk(tree, source, filepath, routes)
    return routes

def _walk(node, source, filepath, routes):
    """Recursively walk the AST looking for app.get/post/put/delete calls."""
    if not isinstance(node, esprima.nodes.Script) and not hasattr(node, 'type'):
        return

    # We're looking for: app.METHOD(path, ...middleware, handler)
    if getattr(node, 'type', None) == 'ExpressionStatement':
        expr = node.expression
        if (getattr(expr, 'type', None) == 'CallExpression' and
                getattr(expr.callee, 'type', None) == 'MemberExpression'):

            obj = expr.callee.object
            prop = expr.callee.property

            # Check it's app.get / router.post etc.
            http_methods = {'get', 'post', 'put', 'delete', 'patch'}
            if getattr(prop, 'name', '').lower() in http_methods:
                args = expr.arguments
                if len(args) >= 2:
                    # First arg should be the path string
                    path_arg = args[0]
                    route_path = path_arg.value if hasattr(path_arg, 'value') else '?'

                    # Middle args are middleware, last is the handler
                    middleware = []
                    for arg in args[1:-1]:
                        if hasattr(arg, 'name'):
                            middleware.append(arg.name)

                    # Last arg is the handler
                    handler_arg = args[-1]
                    handler_name = getattr(handler_arg, 'name', 'anonymous')

                    routes.append(Route(
                        method=prop.name.upper(),
                        path=route_path,
                        middleware=middleware,
                        handler=handler_name,
                        source_file=filepath
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