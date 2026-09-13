import os
from pathlib import Path
from typing import Dict, Any, List
from langchain_community.document_loaders import TextLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_community.vectorstores import FAISS
from langchain_community.embeddings import HuggingFaceEmbeddings

_GLOBAL_EMBEDDINGS = None

def get_shared_embeddings():
    return None

class ContextBuilder:
    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path)
        self.ignore_dirs = {
            '.git', 'node_modules', 'venv', '.venv', '__pycache__', 'dist', 'build',
            '.next', '.cache', 'target', 'out', 'coverage', '.turbo', '.gradle',
            'public', 'assets', '.idea', '.vscode', '.github', 'vendor'
        }
        self.ignore_exts = {
            '.lock', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff',
            '.woff2', '.ttf', '.eot', '.mp4', '.webm', '.map', '.min.js', '.min.css',
            '.pdf', '.zip', '.tar', '.gz', '.db', '.sqlite', '.exe', '.bin'
        }
        self.embeddings = get_shared_embeddings()
        
    def _build_tree(self) -> str:
        """Generates a clean text representation of the directory tree."""
        tree_str = []
        file_count = 0
        max_tree_files = 80
        
        for root, dirs, files in os.walk(self.repo_path):
            dirs[:] = [d for d in dirs if d not in self.ignore_dirs and not d.startswith('.')]
            level = root.replace(str(self.repo_path), '').count(os.sep)
            if level > 4:
                continue
            indent = ' ' * 4 * level
            tree_str.append(f"{indent}{os.path.basename(root)}/")
            subindent = ' ' * 4 * (level + 1)
            for f in files:
                if any(f.endswith(ext) for ext in self.ignore_exts):
                    continue
                file_count += 1
                if file_count <= max_tree_files:
                    tree_str.append(f"{subindent}{f}")
                elif file_count == max_tree_files + 1:
                    tree_str.append(f"{subindent}... [truncated remaining files]")
        return "\n".join(tree_str)

    def _extract_readme(self) -> str:
        """Finds and reads the README file."""
        for file in os.listdir(self.repo_path):
            if file.lower().startswith('readme'):
                try:
                    with open(self.repo_path / file, 'r', encoding='utf-8', errors='ignore') as f:
                        return f.read()[:4000]
                except Exception:
                    pass
        return "No README found."

    def _find_dependencies(self) -> List[str]:
        """Detects basic dependency files."""
        deps = []
        if (self.repo_path / 'package.json').exists():
            deps.append("Node.js (package.json)")
        if (self.repo_path / 'requirements.txt').exists():
            deps.append("Python (requirements.txt)")
        if (self.repo_path / 'pyproject.toml').exists():
            deps.append("Python (pyproject.toml)")
        if (self.repo_path / 'go.mod').exists():
            deps.append("Go (go.mod)")
        if (self.repo_path / 'pom.xml').exists():
            deps.append("Java (pom.xml)")
        if (self.repo_path / 'Cargo.toml').exists():
            deps.append("Rust (Cargo.toml)")
        return deps

    def _build_faiss_index(self) -> str:
        """Returns empty path instantly to avoid CPU model loading delays during real-time ingest."""
        return ""

    def build_context(self) -> Dict[str, Any]:
        """Orchestrates the context building process efficiently."""
        tree = self._build_tree()
        readme = self._extract_readme()
        deps = self._find_dependencies()
        faiss_path = self._build_faiss_index()
        
        return {
            "directory_tree": tree,
            "readme_content": readme,
            "dependencies": deps,
            "faiss_index_path": faiss_path
        }

