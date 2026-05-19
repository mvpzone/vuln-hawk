"""Target application lifecycle manager for live PoC validation.

Manages two containers on an isolated internal bridge network:

  1. Target container — the app under test (Flask/Django)
  2. Sender sandbox  — executes PoC HTTP requests via `docker exec`

Both sit on vulnhawk-poc-net (--internal). Neither can reach the
internet. The sender can reach the target. The host never sends
HTTP to the target directly — all requests go through the sandbox.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Optional

import docker as docker_lib

from vuln_agent.config import (
    LIVE_POC_CONTAINER_NAME,
    LIVE_POC_MAX_RESPONSE_BYTES,
    LIVE_POC_NETWORK,
    LIVE_POC_REQUEST_TIMEOUT,
    LIVE_POC_STARTUP_TIMEOUT,
    TARGET_CONFIGS,
    TargetConfig,
)

SENDER_CONTAINER_NAME = "vulnhawk-poc-sender"
SENDER_IMAGE = "python:3.13-slim"


@dataclass
class TargetState:
    container_id: str
    sender_id: str
    target_url: str
    target_name: str
    network_id: str
    is_running: bool = True


_state: Optional[TargetState] = None


def get_target_state() -> Optional[TargetState]:
    return _state


def _get_client() -> docker_lib.DockerClient:
    return docker_lib.from_env()


def _get_or_create_network(client: docker_lib.DockerClient) -> str:
    try:
        net = client.networks.get(LIVE_POC_NETWORK)
        return net.id
    except docker_lib.errors.NotFound:
        pass
    net = client.networks.create(
        LIVE_POC_NETWORK,
        driver="bridge",
        internal=True,
    )
    return net.id


def _remove_container(client: docker_lib.DockerClient, name: str) -> None:
    try:
        c = client.containers.get(name)
        c.stop(timeout=5)
        c.remove(force=True)
    except docker_lib.errors.NotFound:
        pass


def _build_image(client: docker_lib.DockerClient, config: TargetConfig) -> str:
    tag = f"vulnhawk-target-{config.name}:latest"
    try:
        client.images.get(tag)
    except docker_lib.errors.ImageNotFound:
        print(f"[target_manager] Building image {tag}...", file=sys.stderr)
        client.images.build(path=config.dockerfile_dir, tag=tag, rm=True)
        print(f"[target_manager] Image {tag} built", file=sys.stderr)
    return tag


def _get_container_ip(client: docker_lib.DockerClient, container_id: str) -> str:
    container = client.containers.get(container_id)
    networks = container.attrs["NetworkSettings"]["Networks"]
    for _, net_info in networks.items():
        ip = net_info.get("IPAddress")
        if ip:
            return ip
    raise RuntimeError("Container has no IP address")


def _wait_for_health_via_sender(target_url: str, path: str, timeout: int) -> bool:
    """Health-check the target by running curl inside the sender container."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        result = exec_in_sender(
            f"python3 -c \""
            f"import urllib.request; "
            f"r = urllib.request.urlopen('{target_url}{path}', timeout=3); "
            f"print(r.status)"
            f"\""
        )
        if result["exit_code"] == 0:
            status = result["stdout"].strip()
            print(f"[target_manager] Health check: {status}", file=sys.stderr)
            return True
        time.sleep(2)
    return False


def exec_in_sender(command: str, timeout: int = 30) -> dict:
    """Execute a shell command inside the sender sandbox via docker exec."""
    cmd = [
        "docker", "exec",
        SENDER_CONTAINER_NAME,
        "sh", "-c", command,
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"exit_code": -1, "stdout": "", "stderr": f"Timeout after {timeout}s"}

    return {
        "exit_code": r.returncode,
        "stdout": r.stdout.decode("utf-8", errors="replace")[:LIVE_POC_MAX_RESPONSE_BYTES],
        "stderr": r.stderr.decode("utf-8", errors="replace")[:10240],
    }


def send_request_via_sender(
    method: str,
    url: str,
    headers: dict,
    body: str,
    timeout: int,
) -> dict:
    """Send an HTTP request from inside the sender sandbox container."""
    script = (
        "import json, urllib.request, urllib.error, time\n"
        f"req = urllib.request.Request({url!r}, method={method!r})\n"
    )
    for k, v in headers.items():
        script += f"req.add_header({k!r}, {v!r})\n"

    if body:
        script += f"req.data = {body!r}.encode('utf-8')\n"

    script += (
        "start = time.time()\n"
        "try:\n"
        f"    resp = urllib.request.urlopen(req, timeout={timeout})\n"
        "    body_bytes = resp.read()\n"
        "    result = {'status':'ok','http_status':resp.status,"
        "'response_headers':dict(resp.headers),"
        f"'response_body':body_bytes.decode('utf-8','replace')[:{LIVE_POC_MAX_RESPONSE_BYTES}],"
        "'elapsed_ms':int((time.time()-start)*1000)}\n"
        "except urllib.error.HTTPError as e:\n"
        "    body_bytes = e.read() if hasattr(e,'read') else b''\n"
        "    result = {'status':'ok','http_status':e.code,"
        "'response_headers':dict(e.headers),"
        f"'response_body':body_bytes.decode('utf-8','replace')[:{LIVE_POC_MAX_RESPONSE_BYTES}],"
        "'elapsed_ms':int((time.time()-start)*1000)}\n"
        "except Exception as e:\n"
        "    result = {'status':'error','error':str(e)}\n"
        "print(json.dumps(result))\n"
    )

    r = exec_in_sender(f"python3 -c {_shell_quote(script)}", timeout=timeout + 5)

    if r["exit_code"] != 0:
        return {"status": "error", "error": r["stderr"] or r["stdout"] or "Sender exec failed"}

    try:
        return json.loads(r["stdout"].strip().split("\n")[-1])
    except (json.JSONDecodeError, IndexError):
        return {"status": "error", "error": f"Bad response from sender: {r['stdout'][:500]}"}


def _shell_quote(s: str) -> str:
    """Single-quote a string for sh -c, escaping inner single quotes."""
    return "'" + s.replace("'", "'\"'\"'") + "'"


def start_target(target_name: str) -> dict:
    """Build and start target + sender containers on the isolated network."""
    global _state

    if target_name not in TARGET_CONFIGS:
        return {"status": "error", "error": f"Unknown target: {target_name}. Known: {list(TARGET_CONFIGS.keys())}"}

    config = TARGET_CONFIGS[target_name]

    try:
        client = _get_client()
    except docker_lib.errors.DockerException as exc:
        return {"status": "error", "error": f"Docker not available: {exc}"}

    _remove_container(client, LIVE_POC_CONTAINER_NAME)
    _remove_container(client, SENDER_CONTAINER_NAME)
    network_id = _get_or_create_network(client)
    image_tag = _build_image(client, config)

    # Start target
    print(f"[target_manager] Starting {target_name} on {LIVE_POC_NETWORK}...", file=sys.stderr)
    run_kwargs = dict(
        image=image_tag,
        name=LIVE_POC_CONTAINER_NAME,
        network=LIVE_POC_NETWORK,
        mem_limit="512m",
        cpu_period=100000,
        cpu_quota=50000,
        environment={"ALLOWED_HOSTS": "*", "FLASK_ENV": "development"},
        detach=True,
    )
    if config.command:
        run_kwargs["command"] = list(config.command)
    target_container = client.containers.run(**run_kwargs)

    # Start sender sandbox (same network, no special perms)
    print(f"[target_manager] Starting sender sandbox...", file=sys.stderr)
    sender = client.containers.run(
        image=SENDER_IMAGE,
        name=SENDER_CONTAINER_NAME,
        network=LIVE_POC_NETWORK,
        mem_limit="128m",
        detach=True,
        tty=True,
    )

    target_ip = _get_container_ip(client, target_container.id)
    target_url = f"http://{target_ip}:{config.port}"
    print(f"[target_manager] Target IP: {target_ip}, URL: {target_url}", file=sys.stderr)

    healthy = _wait_for_health_via_sender(target_url, config.health_path, LIVE_POC_STARTUP_TIMEOUT)
    if not healthy:
        _remove_container(client, LIVE_POC_CONTAINER_NAME)
        _remove_container(client, SENDER_CONTAINER_NAME)
        return {"status": "error", "error": f"Target failed health check within {LIVE_POC_STARTUP_TIMEOUT}s"}

    _state = TargetState(
        container_id=target_container.id,
        sender_id=sender.id,
        target_url=target_url,
        target_name=target_name,
        network_id=network_id,
    )

    return {
        "status": "ok",
        "target_url": target_url,
        "message": f"Target {target_name} running at {target_url}. Sender sandbox ready. Analyzers can now use send_poc_request.",
    }


def stop_target() -> dict:
    """Stop and remove target + sender containers and network."""
    global _state

    if _state is None:
        return {"status": "ok", "message": "No target running"}

    try:
        client = _get_client()
        _remove_container(client, SENDER_CONTAINER_NAME)
        _remove_container(client, LIVE_POC_CONTAINER_NAME)
        try:
            net = client.networks.get(LIVE_POC_NETWORK)
            net.remove()
        except (docker_lib.errors.NotFound, docker_lib.errors.APIError):
            pass
    except docker_lib.errors.DockerException as exc:
        return {"status": "error", "error": f"Cleanup failed: {exc}"}
    finally:
        _state = None

    return {"status": "ok", "message": "Target and sender stopped and cleaned up"}
