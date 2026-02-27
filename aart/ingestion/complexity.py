from ingestion.extractor import Route

def detect_tier(routes: list[Route]) -> str:
    """
    Simple:  <= 10 routes  → heuristic fast-path
    Medium:  10-50 routes  → graph + symbolic
    Complex: 50+ routes    → full pipeline
    """
    count = len(routes)
    if count <= 10:
        return "SIMPLE"
    elif count <= 50:
        return "MEDIUM"
    else:
        return "COMPLEX"