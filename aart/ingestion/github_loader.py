import os
import tempfile
import shutil
import re
import logging
import git

logger = logging.getLogger('aart')

def is_github_url(input_str: str) -> bool:
    return bool(re.match(r'(https?://)?(www\.)?github\.com/[\w.-]+/[\w.-]+', input_str))

def normalize_github_url(url: str) -> str:
    if not url.startswith('http'):
        url = 'https://' + url
    if not url.endswith('.git'):
        url = url + '.git'
    return url

def clone_repo(github_url: str) -> tuple[str, callable]:
    url = normalize_github_url(github_url)
    tmp_dir = tempfile.mkdtemp(prefix='aart_')

    logger.info(f"Cloning {url}")
    logger.debug(f"Temp folder: {tmp_dir}")

    try:
        git.Repo.clone_from(url, tmp_dir)
        logger.info("Clone complete")
    except git.exc.GitCommandError as e:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise ValueError(f"Failed to clone repo: {e}")

    def cleanup():
        shutil.rmtree(tmp_dir, ignore_errors=True)
        logger.info("Cleaned up temp folder")

    return tmp_dir, cleanup

"""
The key difference between the log levels being used:

- `logger.info()` — normal progress messages ("Found 5 routes")
- `logger.warning()` — anything security-related that needs attention ("IDOR_CANDIDATE on GET /invoices/:id")
- `logger.debug()` — verbose detail that's hidden by default (individual route listings)

The output will now look like:
```
2026-02-28 10:45:01 [INFO] Loading JS files from: test-app/
2026-02-28 10:45:01 [INFO] Found 1 JS files
2026-02-28 10:45:01 [WARNING] [HIGH] IDOR_CANDIDATE — GET /invoices/:id

"""