import os
import tempfile
import shutil
import re
import git  # from gitpython

def is_github_url(input_str: str) -> bool:
    """
    Check if the input looks like a GitHub URL.
    Handles formats like:
      https://github.com/user/repo
      https://github.com/user/repo.git
      github.com/user/repo
    """
    return bool(re.match(r'(https?://)?(www\.)?github\.com/[\w.-]+/[\w.-]+', input_str))

def normalize_github_url(url: str) -> str:
    """
    Ensure the URL starts with https:// and ends with .git
    so GitPython can clone it reliably.
    """
    if not url.startswith('http'):
        url = 'https://' + url
    if not url.endswith('.git'):
        url = url + '.git'
    return url

def clone_repo(github_url: str) -> tuple[str, callable]:
    """
    Clone a GitHub repo into a temporary directory.

    Returns:
        repo_path: path to the cloned repo on disk
        cleanup:   a function you call when done to delete the temp folder

    Usage:
        repo_path, cleanup = clone_repo(url)
        try:
            # do your analysis on repo_path
        finally:
            cleanup()  # always clean up, even if analysis crashes
    """
    url = normalize_github_url(github_url)

    # Create a temporary directory that won't conflict with anything
    tmp_dir = tempfile.mkdtemp(prefix='aart_')
    print(f"[*] Cloning {url}")
    print(f"[*] Into temp folder: {tmp_dir}")

    try:
        git.Repo.clone_from(url, tmp_dir)
        print(f"[*] Clone complete")
    except git.exc.GitCommandError as e:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise ValueError(f"Failed to clone repo: {e}")

    # Return the path and a cleanup function
    def cleanup():
        shutil.rmtree(tmp_dir, ignore_errors=True)
        print(f"[*] Cleaned up temp folder")

    return tmp_dir, cleanup