# AART — Autonomous API Red Team

> Continuous autonomous security analysis for Node.js/Express APIs — finds real exploit paths, not noise.

AART is a static analysis engine that simulates attacker behavior against API-first web applications. It parses your Express codebase, builds an attack surface graph, and performs AST-level taint tracking to find real, reproducible access-control vulnerabilities — without running your code.

**Built as a university project based on a full product PRD. Currently in active prototype development.**

---

## What It Finds

| Vulnerability | Detection Method | Confidence |
|---|---|---|
| IDOR (Insecure Direct Object Reference) | AST taint tracking | 0.90 |
| Horizontal Privilege Escalation | AST taint tracking | 0.85 |
| Mass Assignment | AST sink analysis | 0.80 |
| Missing Authentication | Heuristic (middleware analysis) | HIGH |
| Vertical Privilege Inconsistency | Graph analysis | MEDIUM |

All of these fall under **Broken Access Control** — the #1 vulnerability class on the OWASP Top 10.

---

## How It Works

AART runs a multi-stage pipeline on your codebase:

```
JS Source Files
      │
      ▼
┌─────────────────┐
│Ingestion Worker │  Parses all .js files into ASTs, extracts routes,
│                 │  middleware chains, and handler bodies
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│Complexity Router│  Classifies repo as Simple / Medium / Complex
│                 │  and routes to appropriate pipeline
└────────┬────────┘
         │
         ├──────────────────────────┐
         ▼                          ▼
┌─────────────────┐      ┌───────────────────────┐
│Heuristic Scanner│      │   Graph Builder       │
│                 │      │                       │
│Fast-path rules  │      │ Builds attack surface │
│on route metadata│      │ graph: routes,        │
│(no AST needed)  │      │ middleware, roles     │
└────────┬────────┘      └──────────┬────────────┘
         │                          │
         │               ┌──────────▼───────────┐
         │               │ Symbolic Lite Engine │
         │               │                      │
         │               │ AST-level taint      │
         │               │ tracking inside      │
         │               │ handler bodies       │
         │               └──────────┬───────────┘
         │                          │
         └──────────────┬───────────┘
                        ▼
         Findings + Confidence Scores
```

### The Symbolic Engine

The core of AART is a deterministic symbolic analysis engine — not an LLM, not regex. It reasons about code structure using AST traversal and taint tracking:

1. **Seed** — identifies variables assigned from `req.params`, `req.body`, or `req.query` (user-controlled inputs)
2. **Propagate** — traces taint through variable assignments across the handler
3. **Sink detection** — finds DB calls (`findById`, `findOne`, `update`, etc.) that receive tainted arguments
4. **Ownership validation** — checks whether a valid ownership comparison (`user._id === req.user.id`) exists before the sink

If tainted data reaches a DB sink without an ownership check → finding generated.

**Example — vulnerable handler (IDOR):**
```js
app.get('/invoices/:id', authMiddleware, async (req, res) => {
    const invoice = await Invoice.findById(req.params.id); // ← tainted sink, no ownership check
    res.json(invoice);
});
// Result: TAINT_NO_OWNERSHIP_CHECK [confidence: 0.90]
```

**Example — safe handler (correctly cleared):**
```js
app.get('/users/:id', authMiddleware, async (req, res) => {
    const user = await User.findById(req.params.id);
    if (user._id.toString() !== req.user.id) { // ← ownership check detected
        return res.status(403).json({ error: 'Forbidden' });
    }
    res.json(user);
});
// Result: No finding — ownership check clears the candidate
```

---

## Getting Started

### Prerequisites

- Python 3.10+
- A Node.js/Express repository to analyze

### Installation

```bash
git clone https://github.com/yourusername/AART.git
cd AART/aart
pip install esprima gitpython
```

### Usage

**Analyze a local repository:**
```bash
python main.py path/to/your/express/app
```

**Analyze a GitHub repository directly:**
```bash
python main.py https://github.com/username/repo
```

AART will clone the repo into a temporary directory, run the full pipeline, and clean up automatically.

### Example Output

```
2026-02-28 03:26:05 [INFO] Extracted 5 routes
2026-02-28 03:26:05 [INFO] Complexity tier: SIMPLE
2026-02-28 03:26:05 [WARNING] [HIGH] IDOR_CANDIDATE — GET /invoices/:id
2026-02-28 03:26:05 [INFO]   Any logged-in user can read anyone else's invoices by changing the ID in the URL.
2026-02-28 03:26:05 [WARNING] [confidence: 0.90] TAINT_NO_OWNERSHIP_CHECK — GET /invoices/:id
2026-02-28 03:26:05 [INFO]   GET /invoices/:id reads user-supplied input directly into a database query without verifying the record belongs to the requesting user.
2026-02-28 03:26:05 [WARNING] [confidence: 0.85] HORIZONTAL_PRIVILEGE_ESCALATION — POST /users/:id
2026-02-28 03:26:05 [INFO]   POST /users/:id allows a logged-in user to modify another user's record by changing the ID in the URL.
```

---

## Project Structure

```
aart/
├── ingestion/
│   ├── loader.py          # Walks repo, loads .js files
│   ├── extractor.py       # AST parser — extracts routes, middleware, handler AST nodes
│   ├── complexity.py      # Classifies repo tier (Simple / Medium / Complex)
│   └── github_loader.py   # Clones GitHub repos into temp directories
├── scanner/
│   └── __init__.py        # Heuristic fast-path scanner (3 rules)
├── graph/
│   └── __init__.py        # Attack surface graph builder + analysis
├── symbolic/
│   └── __init__.py        # AST taint tracker + exploit detection engine
├── reports/               # Report generator (in development)
└── main.py                # Pipeline entry point
```

---

## Complexity Tiers

AART automatically detects repo complexity and adjusts its pipeline:

| Tier | Criteria | Pipeline |
|---|---|---|
| Simple | ≤ 10 routes | Heuristic scanner + symbolic engine |
| Medium | 10–50 routes | + Full graph analysis |
| Complex | 50+ routes | + Extended symbolic passes |

---

## Current Status

This is a university prototype. Here's where development stands against the full PRD:

- [x] Ingestion worker + AST route extractor
- [x] Complexity router
- [x] Heuristic fast-path scanner
- [x] Attack surface graph builder
- [x] AST-based symbolic taint engine (3 exploit classes)
- [x] GitHub URL ingestion
- [x] Structured logging
- [ ] Report generator (JSON + narrative output)
- [ ] App fingerprint / security health grade
- [ ] Threat memory (SQLite)
- [ ] Confidence score unification
- [ ] Sandbox runner (exploit confirmation)
- [ ] GitHub App / PR comment integration

---

## Limitations

- **Node.js/Express only** — TypeScript, Fastify, Django, and FastAPI support planned
- **Inline handlers only** — named handler functions defined outside the route call are not yet analyzed by the symbolic engine (heuristic scanner still covers them)
- **No sandbox confirmation** — findings are candidates, not confirmed exploits. The sandbox runner that would execute and verify candidates is not yet built
- **Public repos only** — private GitHub repo support requires token auth (planned)

---

## Architecture Principles

Taken directly from the PRD:

- **Deterministic authority** — the symbolic engine controls all exploit feasibility decisions. LLMs assist but never confirm exploits
- **Safety first** — no code is executed against real systems. All analysis is static
- **Human in loop** — no automatic changes; developers review and approve all suggestions
- **High signal** — findings require multiple corroborating signals before being surfaced

---

## License

MIT
