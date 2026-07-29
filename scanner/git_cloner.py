"""GitHub repository cloner module."""

import os
import subprocess
import tempfile
import shutil
import re
from urllib.parse import urlparse


class RepoCloner:
    """Clones GitHub repositories for PQC scanning."""

    def __init__(self, timeout: int = 60):
        self.timeout = timeout
        self.temp_dir = None

    def clone(self, repo_url: str) -> str:
        """Clone a GitHub repository to a temporary directory.

        Args:
            repo_url: GitHub repository URL (https://github.com/user/repo)

        Returns:
            Path to cloned repository

        Raises:
            ValueError: If URL is not a valid GitHub URL
            subprocess.CalledProcessError: If git clone fails
        """
        repo_url = self._normalize_url(repo_url)
        self._validate_url(repo_url)

        self.temp_dir = tempfile.mkdtemp(prefix="pg_pqc_scan_")

        try:
            subprocess.run(
                ["git", "clone", "--depth", "1", repo_url, self.temp_dir],
                timeout=self.timeout,
                check=True,
                capture_output=True,
                text=True,
            )
            return self.temp_dir
        except subprocess.TimeoutExpired:
            self.cleanup()
            raise TimeoutError(f"Clone timed out after {self.timeout}s: {repo_url}")
        except subprocess.CalledProcessError as e:
            self.cleanup()
            raise RuntimeError(f"Git clone failed: {e.stderr}")

    def _normalize_url(self, url: str) -> str:
        """Normalize GitHub URL to HTTPS format."""
        url = url.strip().rstrip("/")

        # Convert SSH to HTTPS
        if url.startswith("git@github.com:"):
            url = "https://github.com/" + url.split(":", 1)[1]

        # Add https:// if missing
        if not url.startswith(("http://", "https://", "git://")):
            url = "https://" + url

        return url

    def _validate_url(self, url: str):
        """Validate that URL is a GitHub repository."""
        parsed = urlparse(url)
        if parsed.hostname not in ("github.com", "www.github.com"):
            raise ValueError(f"Not a GitHub URL: {url}")

        path_parts = parsed.path.strip("/").split("/")
        if len(path_parts) < 2:
            raise ValueError(f"Invalid GitHub URL (need user/repo): {url}")

    def cleanup(self):
        """Remove temporary directory."""
        if self.temp_dir and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)
            self.temp_dir = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()
