import sys
import os
import logging

class Color:
    RED     = '\033[91m'
    YELLOW  = '\033[93m'
    GREEN   = '\033[92m'
    CYAN    = '\033[96m'
    BOLD    = '\033[1m'
    RESET   = '\033[0m'


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

    print_summary(all_routes, tier, findings, sym_findings)
    return all_routes, tier, findings, graph, sym_findings

def print_summary(all_routes, tier, findings, sym_findings):
    from scanner import Finding
    from symbolic import SymbolicFinding

    total_findings = len(findings) + len(sym_findings)

    # Determine highest severity across heuristic findings
    severity_rank = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'INFO': 1}
    highest = 'NONE'
    for f in findings:
        if severity_rank.get(f.severity, 0) > severity_rank.get(highest, 0):
            highest = f.severity

    # Collect unique rule names from symbolic findings
    sym_rules = list({f.rule for f in sym_findings})
    rules_str = ', '.join(sym_rules) if sym_rules else 'None'

    # Truncate rules string if too long for the box
    if len(rules_str) > 28:
        rules_str = rules_str[:25] + '...'

    width = 60
    def row(label, value, raw_value=None):
        value = str(value)
        display_len = len(raw_value) if raw_value else len(value)
        padding = width - len(label) - display_len - 4
        return f'{Color.CYAN}║{Color.RESET}  {label}{" " * padding}{value}  {Color.CYAN}║{Color.RESET}'

    print('\n' + Color.CYAN + '╔' + '═' * width + '╗' + Color.RESET)
    print(Color.CYAN + '║' + Color.BOLD + '       AART SCAN COMPLETE'.center(width) + Color.RESET + Color.CYAN + '║' + Color.RESET)
    print(Color.CYAN + '╠' + '═' * width + '╣' + Color.RESET)
    print(row('Routes analyzed:', len(all_routes)))
    print(row('Complexity tier:', tier))
    print(row('Heuristic findings:', len(findings)))
    print(row('Symbolic findings:', len(sym_findings)))
    print(row('Total findings:', total_findings))
    severity_color = {
        'CRITICAL': Color.RED,
        'HIGH':     Color.RED,
        'MEDIUM':   Color.YELLOW,
        'NONE':     Color.GREEN
    }.get(highest, Color.RESET)
    print(row('Highest severity:', severity_color + highest + Color.RESET, raw_value=highest))
    print(row('Symbolic rules fired:', rules_str))
    print(Color.CYAN + '╚' + '═' * width + '╝' + Color.RESET)


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