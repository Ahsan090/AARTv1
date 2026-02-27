import os

def load_js_files(repo_path: str) -> dict[str, str]:
    """
    Walk a repo directory and return a dict of
    { filepath: source_code } for all .js files.
    """
    files = {}
    for root, dirs, filenames in os.walk(repo_path):
        # skip node_modules entirely
        dirs[:] = [d for d in dirs if d != 'node_modules']
        for filename in filenames:
            if filename.endswith('.js'):
                full_path = os.path.join(root, filename)
                with open(full_path, 'r', errors='ignore') as f:
                    files[full_path] = f.read()
    return files