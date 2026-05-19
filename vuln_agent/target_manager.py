"""Target application lifecycle manager for live PoC validation.

Manages Docker containers on an isolated internal bridge network.
The target container:
  - Listens on its designated port
  - Is reachable from the host via the bridge network
  - Cannot access the internet (--internal network)
  - Cannot access cloud metadata or host services
"""

from __future__ import annotations

import sys
import time
from dataclasses import dataclass
from typing import Optional

import docker as docker_lib
import requests as http_requests

from vuln_agent.config import (
    LIVE_POC_CONTAINER_NAME,
    LIVE_POC_NETWORK,
    LIVE_POC_STARTUP_TIMEOUT,
    TARGET_CONFIGS,
    TargetConfig,
)


@dataclass
class TargetState:
    container_id: str
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


def _cleanup_existing(client: docker_lib.DockerClient) -> None:
    try:
        old = client.containers.get(LIVE_POC_CONTAINER_NAME)
        old.stop(timeout=5)
        old.remove(force=True)
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
    for net_name, net_info in networks.items():
        ip = net_info.get("IPAddress")
        if ip:
            return ip
    raise RuntimeError("Container has no IP address")


def _wait_for_health(url: str, path: str, timeout: int) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            resp = http_requests.get(url + path, timeout=2, allow_redirects=True)
            print(f"[target_manager] Health check: {resp.status_code}", file=sys.stderr)
            return True
        except (http_requests.ConnectionError, http_requests.Timeout):
            time.sleep(2)
    return False


def start_target(target_name: str) -> dict:
    """Build and start a target container on the isolated network."""
    global _state

    if target_name not in TARGET_CONFIGS:
        return {"status": "error", "error": f"Unknown target: {target_name}. Known: {list(TARGET_CONFIGS.keys())}"}

    config = TARGET_CONFIGS[target_name]

    try:
        client = _get_client()
    except docker_lib.errors.DockerException as exc:
        return {"status": "error", "error": f"Docker not available: {exc}"}

    _cleanup_existing(client)
    network_id = _get_or_create_network(client)
    image_tag = _build_image(client, config)

    print(f"[target_manager] Starting {target_name} on {LIVE_POC_NETWORK}...", file=sys.stderr)
    container = client.containers.run(
        image=image_tag,
        name=LIVE_POC_CONTAINER_NAME,
        network=LIVE_POC_NETWORK,
        mem_limit="512m",
        cpu_period=100000,
        cpu_quota=50000,
        detach=True,
    )

    ip = _get_container_ip(client, container.id)
    target_url = f"http://{ip}:{config.port}"
    print(f"[target_manager] Container IP: {ip}, URL: {target_url}", file=sys.stderr)

    healthy = _wait_for_health(target_url, config.health_path, LIVE_POC_STARTUP_TIMEOUT)
    if not healthy:
        container.stop(timeout=5)
        container.remove(force=True)
        return {"status": "error", "error": f"Target failed to become healthy within {LIVE_POC_STARTUP_TIMEOUT}s"}

    _state = TargetState(
        container_id=container.id,
        target_url=target_url,
        target_name=target_name,
        network_id=network_id,
    )

    return {
        "status": "ok",
        "target_url": target_url,
        "message": f"Target {target_name} running at {target_url}. Analyzers can now use send_poc_request.",
    }


def stop_target() -> dict:
    """Stop and remove the target container and network."""
    global _state

    if _state is None:
        return {"status": "ok", "message": "No target running"}

    try:
        client = _get_client()
        _cleanup_existing(client)
        try:
            net = client.networks.get(LIVE_POC_NETWORK)
            net.remove()
        except (docker_lib.errors.NotFound, docker_lib.errors.APIError):
            pass
    except docker_lib.errors.DockerException as exc:
        return {"status": "error", "error": f"Cleanup failed: {exc}"}
    finally:
        _state = None

    return {"status": "ok", "message": "Target stopped and cleaned up"}
