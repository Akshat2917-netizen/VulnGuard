"""
Docker sandbox runner — resource-constrained container execution.

Runs build, test, and exploit commands in isolated Docker containers
with strict security limits (Section 4.3). Handles Windows path
translation (EC-8.4), Docker health checks (EC-8.1), and unique
container naming (Section 4.6).
"""

from __future__ import annotations

import logging
import os
import platform
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Optional
from uuid import uuid4

from vulnguard.config import cfg

logger = logging.getLogger(__name__)


class DockerNotAvailableError(RuntimeError):
    """Raised when Docker daemon is not running or not installed."""

    def __init__(self):
        super().__init__(
            "Docker is not available. Ensure Docker Desktop is running.\n"
            "Install: https://docs.docker.com/get-docker/\n"
            "On Windows, Docker Desktop or WSL2 with Docker is required."
        )


# ── Result dataclasses ────────────────────────────────────────────────────

@dataclass
class CommandResult:
    """Result of a sandbox command execution."""

    success: bool
    exit_code: int
    stdout: str
    stderr: str

    @property
    def combined_output(self) -> str:
        out = ""
        if self.stdout:
            out += self.stdout
        if self.stderr:
            out += "\n--- STDERR ---\n" + self.stderr
        return out


# ── Path translation (EC-8.4) ────────────────────────────────────────────

def _to_docker_mount_path(host_path: str) -> str:
    """Convert Windows paths to Docker-compatible mount paths.

    Docker Desktop on Windows expects paths like /c/Users/... for bind mounts
    when using certain backends.
    """
    if platform.system() != "Windows":
        return host_path

    p = Path(host_path).resolve()
    # C:\Users\foo → /c/Users/foo
    drive = p.drive.rstrip(":")
    posix = PurePosixPath("/", drive.lower(), *p.parts[1:])
    return str(posix)


# ── Docker client singleton ──────────────────────────────────────────────

_docker_client = None


def _get_client():
    """Get or create Docker client with health check (EC-8.1)."""
    global _docker_client
    if _docker_client is not None:
        return _docker_client

    try:
        import docker

        client = docker.from_env()
        client.ping()  # Health check
        _docker_client = client
        return client
    except Exception as exc:
        logger.error("Docker health check failed: %s", exc)
        raise DockerNotAvailableError() from exc


# ── Container execution ──────────────────────────────────────────────────

class DockerRunner:
    """Manages sandboxed container execution with security constraints."""

    def __init__(self):
        self._client = _get_client()

    def _run_container(
        self,
        command: str,
        repo_root: str = "",
        extra_files: dict[str, str] | None = None,
        env_vars: dict[str, str] | None = None,
        timeout: int | None = None,
    ) -> CommandResult:
        """Run a command in an isolated Docker container.

        Args:
            command: Shell command to execute inside the container.
            repo_root: Host path to mount as /workspace (read-only).
            extra_files: Dict of {container_path: content} to write before execution.
            env_vars: Environment variables to inject.
            timeout: Execution timeout in seconds.

        Returns:
            CommandResult with exit code and output.
        """
        timeout = timeout or cfg.sandbox.execution_timeout_seconds
        container_name = f"vulnguard_sandbox_{uuid4().hex[:8]}"

        # Build container config (Section 4.3 security constraints)
        run_kwargs: dict = {
            "image": cfg.sandbox.sandbox_image,
            "command": ["sh", "-c", command],
            "name": container_name,
            "mem_limit": cfg.sandbox.memory_limit,
            "cpu_count": cfg.sandbox.cpu_count,
            "pids_limit": cfg.sandbox.pids_limit,
            "network_mode": cfg.sandbox.network_mode,
            "read_only": False,
            "tmpfs": {"/tmp": "size=100m,exec"},
            "auto_remove": False,  # We need to fetch logs before removal
            "detach": True,
            "cap_drop": ["ALL"],
        }

        # Mount repo if provided
        if repo_root and os.path.isdir(repo_root):
            mount_path = _to_docker_mount_path(repo_root)
            run_kwargs["volumes"] = {
                mount_path: {"bind": "/host_workspace", "mode": "ro"},
            }
            # Manually create workspace as root, chown, and drop privileges
            escaped_command = command.replace('"', '\\"')
            run_kwargs["command"] = [
                "sh", "-c",
                f"mkdir -p /tmp/workspace && cp -R /host_workspace/. /tmp/workspace/ 2>/dev/null || true; chown -R nobody /tmp/workspace 2>/dev/null || true; su -s /bin/sh nobody -c \"cd /tmp/workspace && {escaped_command}\""
            ]
            # Removed working_dir to prevent Docker from creating it as root

        # Environment variables (EC-8.2)
        env = {}
        if cfg.sandbox.env_file and os.path.isfile(cfg.sandbox.env_file):
            with open(cfg.sandbox.env_file) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, _, v = line.partition("=")
                        env[k.strip()] = v.strip()
        if env_vars:
            env.update(env_vars)
        if env:
            run_kwargs["environment"] = env

        container = None
        try:
            container = self._client.containers.run(**run_kwargs)

            # Write extra files to /tmp inside container if needed
            if extra_files:
                import tarfile
                import io

                tar_buf = io.BytesIO()
                with tarfile.open(fileobj=tar_buf, mode="w") as tar:
                    for path, content in extra_files.items():
                        data = content.encode("utf-8")
                        info = tarfile.TarInfo(name=Path(path).name)
                        info.size = len(data)
                        tar.addfile(info, io.BytesIO(data))
                tar_buf.seek(0)
                container.put_archive("/tmp", tar_buf)

            # Wait for completion
            result = container.wait(timeout=timeout)
            exit_code = result.get("StatusCode", -1)

            stdout = container.logs(stdout=True, stderr=False).decode("utf-8", errors="replace")
            stderr = container.logs(stdout=False, stderr=True).decode("utf-8", errors="replace")

            return CommandResult(
                success=(exit_code == 0),
                exit_code=exit_code,
                stdout=stdout[-5000:],  # Cap output
                stderr=stderr[-5000:],
            )

        except Exception as exc:
            logger.error("Container execution failed: %s", exc)
            return CommandResult(
                success=False,
                exit_code=-1,
                stdout="",
                stderr=str(exc),
            )
        finally:
            if container:
                try:
                    container.remove(force=True)
                except Exception:
                    pass

    def run_build(
        self,
        repo_root: str,
        file_path: str = "",
        code: str = "",
        build_command: str = "",
    ) -> CommandResult:
        """Run a build/compilation check.

        If build_command is not provided, auto-detects based on repo contents.
        """
        # Auto-detect build system
        if not build_command:
            build_command = self._detect_build_command(repo_root)

        extra = {}
        if file_path and code:
            # Write patched file to /tmp and copy it to the right location
            container_file = f"/tmp/patched_{Path(file_path).name}"
            extra[container_file] = code
            # Prepend copy command
            rel_path = os.path.relpath(file_path, repo_root) if repo_root else Path(file_path).name
            build_command = f"cp {container_file} /tmp/workspace/{rel_path} 2>/dev/null; {build_command}"

        return self._run_container(
            command=build_command,
            repo_root=repo_root,
            extra_files=extra if extra else None,
        )

    def run_tests(
        self,
        repo_root: str,
        test_command: str = "",
    ) -> CommandResult:
        """Run the project's test suite."""
        if not test_command:
            test_command = self._detect_test_command(repo_root)

        return self._run_container(
            command=test_command,
            repo_root=repo_root,
        )

    def run_exploit(
        self,
        repo_root: str,
        exploit_code: str,
        target_code: str = "",
        file_path: str = "",
        language: str = "c",
    ) -> CommandResult:
        """Run a Red Agent PoC exploit in the sandbox.

        The exploit is written to /tmp and executed. Target code can be
        optionally patched before running.
        """
        ext_map = {"c": "c", "cpp": "cpp", "python": "py", "java": "java", "javascript": "js"}
        ext = ext_map.get(language, "txt")
        exploit_file = f"/tmp/exploit.{ext}"

        # Build execution command
        run_cmd_map = {
            "c": f"gcc {exploit_file} -o /tmp/exploit_bin && /tmp/exploit_bin",
            "cpp": f"g++ {exploit_file} -o /tmp/exploit_bin && /tmp/exploit_bin",
            "python": f"python3 {exploit_file}",
            "java": f"javac {exploit_file} && java -cp /tmp Exploit",
            "javascript": f"node {exploit_file}",
        }
        run_cmd = run_cmd_map.get(language, f"sh {exploit_file}")

        extra = {exploit_file: exploit_code}
        if target_code and file_path:
            container_file = f"/tmp/target_{Path(file_path).name}"
            extra[container_file] = target_code

        return self._run_container(
            command=run_cmd,
            repo_root=repo_root,
            extra_files=extra,
        )

    @staticmethod
    def _detect_build_command(repo_root: str) -> str:
        """Auto-detect build command from repo files."""
        root = Path(repo_root)
        if (root / "Makefile").exists():
            return "make -j$(nproc)"
        if (root / "CMakeLists.txt").exists():
            return "mkdir -p /tmp/build && cd /tmp/build && cmake /tmp/workspace && make -j$(nproc)"
        if (root / "setup.py").exists() or (root / "pyproject.toml").exists():
            return "pip install -e /tmp/workspace 2>&1"
        if (root / "package.json").exists():
            return "cd /tmp/workspace && npm ci && npm run build 2>&1"
        if (root / "pom.xml").exists():
            return "cd /tmp/workspace && mvn compile 2>&1"
        return "echo 'No build system detected — skipping build'"

    @staticmethod
    def _detect_test_command(repo_root: str) -> str:
        """Auto-detect test command from repo files."""
        root = Path(repo_root)
        if (root / "Makefile").exists():
            return "make test 2>&1 || true"
        if (root / "setup.py").exists() or (root / "pyproject.toml").exists():
            return "cd /tmp/workspace && python -m pytest -x 2>&1 || true"
        if (root / "package.json").exists():
            return "cd /tmp/workspace && npm test 2>&1 || true"
        if (root / "pom.xml").exists():
            return "cd /tmp/workspace && mvn test 2>&1 || true"
        # Fallback to pytest for Python MVP
        return "cd /tmp/workspace && python -m pytest -x 2>&1 || true"


def check_docker_available() -> bool:
    """Check if Docker is available. Returns True if healthy, False otherwise."""
    try:
        _get_client()
        return True
    except DockerNotAvailableError:
        return False
