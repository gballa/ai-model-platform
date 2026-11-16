"""Opaque-box CLI invocation harness supporting both in-process and subprocess execution."""
from __future__ import annotations

from dataclasses import dataclass
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent


@dataclass(frozen=True)
class CliResult:
    """Encapsulates the result of a platform CLI execution."""

    exit_code: int
    stdout: str
    stderr: str
    json_data: dict[str, Any] | None
    elapsed_ms: float

    @property
    def is_success(self) -> bool:
        return self.exit_code == 0


class CliRunner:
    """Invokes platform CLI commands either via isolated subprocess or fast in-process capture."""

    _inprocess_lock = threading.RLock()

    def __init__(self, default_mode: str = "inprocess") -> None:
        self.default_mode = default_mode

    def run(
        self,
        args: list[str],
        stdin_text: str | None = None,
        mode: str | None = None,
        env_overrides: dict[str, str] | None = None,
        timeout_sec: float = 60.0,
    ) -> CliResult:
        exec_mode = mode or self.default_mode
        if exec_mode == "subprocess":
            return self._run_subprocess(args, stdin_text, env_overrides, timeout_sec)
        return self._run_inprocess(args, stdin_text)

    invoke = run

    def _run_subprocess(
        self,
        args: list[str],
        stdin_text: str | None,
        env_overrides: dict[str, str] | None,
        timeout_sec: float,
    ) -> CliResult:
        env = dict(os.environ)
        src_path = str(REPO_ROOT / "src")
        existing_pp = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = f"{src_path}{os.pathsep}{existing_pp}" if existing_pp else src_path
        if env_overrides:
            env.update(env_overrides)

        start = time.perf_counter()
        try:
            proc = subprocess.run(
                [sys.executable, "-W", "error", "-m", "platform_core.cli", *args],
                cwd=str(REPO_ROOT),
                env=env,
                input=stdin_text,
                capture_output=True,
                text=True,
                timeout=timeout_sec,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raw_stdout = exc.stdout
            stdout_str = (
                raw_stdout.decode("utf-8", errors="replace")
                if isinstance(raw_stdout, (bytes, bytearray))
                else (raw_stdout or "")
            )
            return CliResult(
                exit_code=124,
                stdout=stdout_str,
                stderr=f"Command timed out after {timeout_sec}s",
                json_data=None,
                elapsed_ms=timeout_sec * 1000.0,
            )

        elapsed = (time.perf_counter() - start) * 1000.0

        parsed_json = None
        try:
            parsed_json = json.loads(proc.stdout)
        except Exception:
            pass

        return CliResult(
            exit_code=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            json_data=parsed_json,
            elapsed_ms=elapsed,
        )

    def _run_inprocess(self, args: list[str], stdin_text: str | None) -> CliResult:
        from platform_core.cli import main as cli_main

        with self._inprocess_lock:
            old_stdin, old_stdout, old_stderr = sys.stdin, sys.stdout, sys.stderr
            in_buf = io.StringIO(stdin_text or "")
            out_buf = io.StringIO()
            err_buf = io.StringIO()
            start = time.perf_counter()

            exit_code = 0
            try:
                sys.stdin = in_buf
                sys.stdout = out_buf
                sys.stderr = err_buf
                exit_code = cli_main(args)
            except SystemExit as exc:
                if exc.code is None:
                    exit_code = 0
                elif isinstance(exc.code, int):
                    exit_code = exc.code
                else:
                    exit_code = 1
            except Exception as exc:
                err_buf.write(f"Unhandled exception: {exc}\n")
                exit_code = 1
            finally:
                sys.stdin, sys.stdout, sys.stderr = old_stdin, old_stdout, old_stderr

            elapsed = (time.perf_counter() - start) * 1000.0
            out_str = out_buf.getvalue()
            err_str = err_buf.getvalue()

        parsed_json = None
        try:
            parsed_json = json.loads(out_str)
        except Exception:
            pass

        return CliResult(
            exit_code=exit_code,
            stdout=out_str,
            stderr=err_str,
            json_data=parsed_json,
            elapsed_ms=elapsed,
        )
