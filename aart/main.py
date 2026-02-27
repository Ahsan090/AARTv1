import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ingestion.loader import load_js_files
from ingestion.extractor import extract_routes
from ingestion.complexity import detect_tier
from ingestion.github_loader import is_github_url, clone_repo
from scanner import run_heuristic_scanner
from graph import build_graph
from symbolic import run_symbolic_engine

def ingest(repo_path: str):
    print(f"[*] Loading JS files from: {repo_path}")
    files = load_js_files(repo_path)
    print(f"[*] Found {len(files)} JS files\n")

    all_routes = []
    for filepath, source in files.items():
        routes = extract_routes(filepath, source)
        all_routes.extend(routes)

    print(f"[*] Extracted {len(all_routes)} routes")
    for r in all_routes:
        print(f"    {r.method} {r.path} | middleware: {r.middleware} | handler: {r.handler}")

    tier = detect_tier(all_routes)
    print(f"\n[*] Complexity tier: {tier}")

    print(f"\n[*] Running heuristic scanner...")
    findings = run_heuristic_scanner(all_routes)
    print(f"[*] Found {len(findings)} findings:\n")
    for f in findings:
        print(f"  [{f.severity}] {f.rule}")
        print(f"  Route: {f.route.method} {f.route.path}")
        print(f"  {f.plain_english}\n")

    print(f"\n[*] Building attack surface graph...")
    graph = build_graph(all_routes)
    graph.summary()

    print(f"\n[*] Graph analysis:")
    unprotected = graph.find_unprotected_paths()
    if unprotected:
        print(f"  [!] Unprotected routes:")
        for node in unprotected:
            print(f"      {node.label}")
    else:
        print(f"  [✓] All routes have at least one middleware")

    gaps = graph.find_privilege_gaps()
    if gaps:
        print(f"\n  [!] Privilege gaps detected:")
        for elevated, normal in gaps:
            print(f"      '{normal.label}' is less protected than '{elevated.label}'")

    print(f"\n[*] Running symbolic engine...")
    sym_findings = run_symbolic_engine(all_routes, files)
    print(f"[*] Found {len(sym_findings)} symbolic findings:\n")
    for f in sym_findings:
        print(f"  [confidence: {f.confidence}] {f.rule}")
        print(f"  Route: {f.route.method} {f.route.path}")
        print(f"  Evidence: {f.evidence}")
        print(f"  {f.plain_english}\n")

    return all_routes, tier, findings, graph, sym_findings


if __name__ == "__main__":
    user_input = sys.argv[1] if len(sys.argv) > 1 else "."

    if is_github_url(user_input):
        # GitHub URL path — clone first, analyze, then clean up
        repo_path, cleanup = clone_repo(user_input)
        try:
            ingest(repo_path)
        finally:
            cleanup()  # runs even if ingest() crashes
    else:
        # Local path — existing behaviour, nothing changes
        ingest(user_input)