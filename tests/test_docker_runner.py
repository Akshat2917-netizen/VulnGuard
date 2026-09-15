"""
Tests for the Docker runner module.

Tests path translation, health checks, and configuration — without
requiring Docker to be installed.
"""

import platform
import pytest
from unittest.mock import patch, MagicMock

from vulnguard.sandbox.docker_runner import (
    _to_docker_mount_path,
    DockerNotAvailableError,
    CommandResult,
    DockerRunner,
)


class TestPathTranslation:
    """Test EC-8.4: Windows path translation."""

    @patch("vulnguard.sandbox.docker_runner.platform")
    def test_windows_path_conversion(self, mock_platform):
        mock_platform.system.return_value = "Windows"
        result = _to_docker_mount_path(r"C:\Users\test\repo")
        assert result.startswith("/c/")
        assert "Users" in result
        assert "\\" not in result

    @patch("vulnguard.sandbox.docker_runner.platform")
    def test_linux_path_unchanged(self, mock_platform):
        mock_platform.system.return_value = "Linux"
        path = "/home/user/repo"
        assert _to_docker_mount_path(path) == path


class TestDockerNotAvailable:
    """Test EC-8.1: Graceful Docker unavailability."""

    def test_error_message(self):
        err = DockerNotAvailableError()
        assert "Docker is not available" in str(err)
        assert "docs.docker.com" in str(err)


class TestCommandResult:
    def test_success_result(self):
        result = CommandResult(success=True, exit_code=0, stdout="OK", stderr="")
        assert result.success
        assert "OK" in result.combined_output

    def test_failure_result(self):
        result = CommandResult(success=False, exit_code=1, stdout="", stderr="error: build failed")
        assert not result.success
        assert "error" in result.combined_output

    def test_combined_output_includes_stderr(self):
        result = CommandResult(success=False, exit_code=1, stdout="line1", stderr="err1")
        combined = result.combined_output
        assert "line1" in combined
        assert "err1" in combined


class TestBuildCommandDetection:
    """Test auto-detection of build systems."""

    def test_makefile_detected(self, tmp_path):
        (tmp_path / "Makefile").write_text("all:\n\tgcc -o main main.c")
        cmd = DockerRunner._detect_build_command(str(tmp_path))
        assert "make" in cmd

    def test_cmake_detected(self, tmp_path):
        (tmp_path / "CMakeLists.txt").write_text("cmake_minimum_required(VERSION 3.10)")
        cmd = DockerRunner._detect_build_command(str(tmp_path))
        assert "cmake" in cmd

    def test_python_project_detected(self, tmp_path):
        (tmp_path / "setup.py").write_text("from setuptools import setup")
        cmd = DockerRunner._detect_build_command(str(tmp_path))
        assert "pip" in cmd

    def test_node_project_detected(self, tmp_path):
        (tmp_path / "package.json").write_text('{"name": "test"}')
        cmd = DockerRunner._detect_build_command(str(tmp_path))
        assert "npm" in cmd

    def test_no_build_system(self, tmp_path):
        cmd = DockerRunner._detect_build_command(str(tmp_path))
        assert "No build system" in cmd
