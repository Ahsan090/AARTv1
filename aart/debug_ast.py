from symbolic import TaintTracker, _find_tainted_db_calls
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import esprima
import json

# Parse the test app
with open('test_app/app.js', 'r') as f:
    source = f.read()

tree = esprima.parseScript(source, tolerant=True, range=True)

def node_to_dict(node):
    """Convert esprima node to plain dict for printing"""
    if node is None:
        return None
    if isinstance(node, list):
        return [node_to_dict(i) for i in node]
    if not hasattr(node, '__dict__'):
        return node
    return {k: node_to_dict(v) for k, v in node.__dict__.items()}

# Find the first inline handler and print its body AST
from ingestion.extractor import extract_routes
routes = extract_routes('test_app/app.js', source)

for route in routes:
    if route.handler_ast is not None:
        print(f"\nRoute: {route.method} {route.path}")
        
        tracker = TaintTracker()
        
        # Manually run seed and print what it finds
        print(f"Running seed...")
        tracker.seed(route.handler_ast)
        print(f"Taint set after seed: {tracker.tainted}")
        
        tracker.propagate(route.handler_ast)
        print(f"Taint set after propagate: {tracker.tainted}")
        
        sinks = _find_tainted_db_calls(route.handler_ast, tracker)
        print(f"Tainted DB calls: {sinks}")
        
        break