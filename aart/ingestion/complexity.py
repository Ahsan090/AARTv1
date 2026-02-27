# Notes from Ahsan
# This file is responsible for determining the complexity tier of a repo based on the number of routes.
# The logic is simple: 
# Simple:  <= 10 routes  → heuristic fast-path
# Medium:  10-50 routes  → graph + symbolic
# Complex: 50+ routes    → full pipeline
# This is done all according to our PRD document.

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