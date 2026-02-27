import sys
import os
import logging

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ingestion.loader import load_js_files
from ingestion.extractor import extract_routes
from ingestion.complexity import detect_tier
from ingestion.github_loader import is_github_url, clone_repo
from scanner import run_heuristic_scanner
from graph import build_graph
from symbolic import run_symbolic_engine

# If you ever want to see the debug-level route listings, just change logging.INFO to logging.DEBUG in the basicConfig line.
# Configure logging — change INFO to DEBUG for more detail, WARNING for less
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('aart')


def ingest(repo_path: str):
    logger.info(f"Loading JS files from: {repo_path}")
    files = load_js_files(repo_path)
    logger.info(f"Found {len(files)} JS files")

    all_routes = []
    for filepath, source in files.items():
        routes = extract_routes(filepath, source)
        all_routes.extend(routes)

    logger.info(f"Extracted {len(all_routes)} routes")
    for r in all_routes:
        logger.debug(f"  {r.method} {r.path} | middleware: {r.middleware} | handler: {r.handler}")

    tier = detect_tier(all_routes)
    logger.info(f"Complexity tier: {tier}")

    logger.info("Running heuristic scanner...")
    findings = run_heuristic_scanner(all_routes)
    logger.info(f"Heuristic scanner found {len(findings)} findings")
    for f in findings:
        logger.warning(f"[{f.severity}] {f.rule} — {f.route.method} {f.route.path}")
        logger.info(f"  {f.plain_english}")

    logger.info("Building attack surface graph...")
    graph = build_graph(all_routes)
    logger.info(f"Graph built: {len(graph.nodes)} nodes, {len(graph.edges)} edges")

    unprotected = graph.find_unprotected_paths()
    if unprotected:
        for node in unprotected:
            logger.warning(f"Unprotected route (no middleware): {node.label}")
    else:
        logger.info("All routes have at least one middleware")

    gaps = graph.find_privilege_gaps()
    for elevated, normal in gaps:
        logger.warning(f"Privilege gap: '{normal.label}' is less protected than '{elevated.label}'")

    logger.info("Running symbolic engine...")
    sym_findings = run_symbolic_engine(all_routes, files)
    logger.info(f"Symbolic engine found {len(sym_findings)} findings")
    for f in sym_findings:
        logger.warning(f"[confidence: {f.confidence}] {f.rule} — {f.route.method} {f.route.path}")
        logger.info(f"  {f.plain_english}")

    return all_routes, tier, findings, graph, sym_findings


if __name__ == "__main__":
    user_input = sys.argv[1] if len(sys.argv) > 1 else "."

    if is_github_url(user_input):
        repo_path, cleanup = clone_repo(user_input)
        try:
            ingest(repo_path)
        finally:
            cleanup()
    else:
        ingest(user_input)