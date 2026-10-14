# PhishGuard

Phishing URL/email classifier served as a containerized FastAPI microservice:
lexical + host-based features, a tree-ensemble model, defensive input handling,
and graceful degradation when WHOIS is slow or unavailable.

> Work in progress. This is the Step 2 stub; the full README lands in Step 15.

## Quickstart (available as steps land)

    uv sync --all-extras   # Step 2
    make test              # Step 2
    make train             # Step 8
    make run               # Step 9
    make demo              # Step 12 (Docker)
