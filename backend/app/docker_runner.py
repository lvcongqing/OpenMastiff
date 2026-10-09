from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional



@dataclass(frozen=True)
class RunResult:
    exit_code: int
    mode: str


def docker_client():
    docker_host = os.getenv("DOCKER_HOST")
    import docker  # lazy import

    if docker_host:
        return docker.DockerClient(base_url=docker_host)
    return docker.from_env()


def _build_scanner_env(
    *,
    input_dir: str,
    output_dir: str,
    policy_dir: str,
    extra: Dict[str, str],
) -> Dict[str, str]:
    """构建扫描子进程环境（勿使用 Celery 进程的 os.environ.copy）。"""
    env: Dict[str, str] = {
        "PATH": "/usr/local/bin:/usr/local/go/bin:/usr/bin:/bin",
        "HOME": os.environ.get("HOME", "/root"),
        "LANG": "C.UTF-8",
        "JAVA_HOME": os.environ.get("JAVA_HOME") or next(
            (
                p
                for p in (
                    "/usr/lib/jvm/jre-17",
                    "/usr/lib/jvm/jre-17-openjdk",
                    "/usr/lib/jvm/java-17-openjdk",
                    "/usr/lib/jvm/java-11-openjdk",
                )
                if os.path.isdir(p)
            ),
            "/usr/lib/jvm/jre-17",
        ),
        "CARGO_HOME": os.environ.get("CARGO_HOME") or os.path.join(os.environ.get("HOME", "/root"), ".cargo"),
        "GOPROXY": os.environ.get("GOPROXY") or "https://goproxy.cn,direct",
        "GOPATH": os.environ.get("GOPATH") or "/root/go",
        "GOMODCACHE": os.environ.get("GOMODCACHE") or "/root/go/pkg/mod",
        "INPUT_DIR": os.path.abspath(input_dir),
        "OUTPUT_DIR": os.path.abspath(output_dir),
        "POLICY_FILE": os.path.abspath(os.path.join(policy_dir, "policy.json")),
    }
    for key in ("SCANNER_MODE", "WORK_ROOT", "BLOB_ROOT"):
        val = os.environ.get(key)
        if val:
            env[key] = val
    env.update(extra)
    for key in (
        "SCAN_ID",
        "REQUEST_ID",
        "SCOPE_MODE",
        "INCLUDE_PATHS",
        "EXCLUDE_DIRS",
        "NETWORK_MODE",
        "TIMEOUT_LICENSE_MIN",
        "TIMEOUT_SYFT_MIN",
        "TIMEOUT_GOSEC_MIN",
        "TIMEOUT_CPPCHECK_MIN",
        "TIMEOUT_LANG_SAST_MIN",
        "TIMEOUT_CVE_MIN",
        "GOSEC_ENABLED",
        "INPUT_SHA256",
        "GRYPE_DB_CACHE_DIR",
        "GRYPE_CHECK_FOR_APP_UPDATE",
        "GRYPE_DB_AUTO_UPDATE",
    ):
        if key in env and env[key] is not None:
            env[key] = str(env[key])
    return env


def run_scanner_container(
    *,
    image: str,
    input_dir: str,
    output_dir: str,
    policy_dir: str,
    env: Dict[str, str],
    network_mode: str = "none",
    extra_volumes: Optional[Dict[str, dict]] = None,
) -> RunResult:
    if os.getenv("SCANNER_MODE") == "local":
        return run_scanner_local(input_dir=input_dir, output_dir=output_dir, policy_dir=policy_dir, env=env)

    client = docker_client()
    volumes = {
        os.path.abspath(input_dir): {"bind": "/input", "mode": "ro"},
        os.path.abspath(output_dir): {"bind": "/output", "mode": "rw"},
        os.path.abspath(policy_dir): {"bind": "/policy", "mode": "ro"},
    }
    if extra_volumes:
        volumes.update(extra_volumes)

    container = client.containers.run(
        image=image,
        detach=True,
        environment=env,
        volumes=volumes,
        network_mode=network_mode,
        read_only=True,
        cap_drop=["ALL"],
        security_opt=["no-new-privileges:true"],
        pids_limit=256,
        mem_limit="2g",
        cpu_period=100000,
        cpu_quota=200000,  # 2 CPUs
    )
    try:
        res = container.wait(timeout=3600)
        status_code = int(res.get("StatusCode", 1))
        return RunResult(exit_code=status_code, mode="docker")
    finally:
        try:
            container.remove(force=True)
        except Exception:
            pass


def run_scanner_local(*, input_dir: str, output_dir: str, policy_dir: str, env: Dict[str, str]) -> RunResult:
    """
    Dev fallback when Docker is unavailable.
    通过新的 Python 子进程执行 run_scan.sh，与 Celery worker 进程隔离。
    """
    repo_root = Path(__file__).resolve().parents[2]
    helper = repo_root / "backend" / "scripts" / "run_local_scanner.py"
    if not helper.is_file():
        raise RuntimeError("local scanner helper not found")

    scanner_env = _build_scanner_env(
        input_dir=input_dir,
        output_dir=output_dir,
        policy_dir=policy_dir,
        extra=env,
    )
    os.makedirs(scanner_env["OUTPUT_DIR"], exist_ok=True)
    payload = json.dumps({"env": scanner_env})
    launcher_env = {"PATH": "/usr/bin:/bin", "HOME": scanner_env["HOME"]}
    proc = subprocess.run(
        [sys.executable, str(helper), payload, str(repo_root)],
        env=launcher_env,
        start_new_session=True,
    )
    return RunResult(exit_code=int(proc.returncode), mode="local")
