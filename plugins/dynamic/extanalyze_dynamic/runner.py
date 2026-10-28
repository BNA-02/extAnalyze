"""Host side: run the extension in a hardened, disposable Docker container and return the
validated observations. Executes untrusted code ONLY inside the container."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import uuid
from importlib import resources
from pathlib import Path

from . import __version__
from .schema import MAX_OUTPUT_BYTES, InvalidDriverOutput, validate

REGISTRY_IMAGE = "ghcr.io/bna-02/extanalyze-sandbox"
LOCAL_IMAGE = "extanalyze-sandbox"
TARGETS = ("chromium-mv3", "chromium-mv2", "firefox")


class DynamicUnavailable(RuntimeError):
    """Docker or the sandbox image is missing."""


def pick_target(browser: str, manifest_version: int) -> str:
    if browser == "firefox":
        return "firefox"
    return "chromium-mv2" if manifest_version == 2 else "chromium-mv3"


def _docker(*args: str, timeout: int = 60, check: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["docker", *args], capture_output=True, text=True, timeout=timeout, check=check
    )


def require_docker() -> None:
    if shutil.which("docker") is None:
        raise DynamicUnavailable("Docker is required for --dynamic but was not found in PATH")
    try:
        if _docker("info", timeout=20).returncode != 0:
            raise DynamicUnavailable("Docker is installed but the daemon is not reachable")
    except subprocess.TimeoutExpired as e:
        raise DynamicUnavailable("Docker daemon did not respond") from e


def resolve_image(target: str) -> str:
    """Prefer a locally built image, then the published one for this plugin version."""
    local = f"{LOCAL_IMAGE}:{target}"
    if _docker("image", "inspect", local).returncode == 0:
        return local
    remote = f"{REGISTRY_IMAGE}:{target}-{__version__}"
    if _docker("image", "inspect", remote).returncode == 0:
        return remote
    raise DynamicUnavailable(
        f"Sandbox image for {target} not found. Run `extanalyze dynamic pull` "
        "(or `extanalyze dynamic build`)."
    )


def pull_image(target: str) -> str:
    ref = f"{REGISTRY_IMAGE}:{target}-{__version__}"
    _docker("pull", ref, timeout=1800, check=True)
    return ref


def build_image(target: str) -> str:
    """Build a sandbox image from the Dockerfile bundled with the plugin."""
    ref = f"{LOCAL_IMAGE}:{target}"
    src = resources.files("extanalyze_dynamic") / "sandbox"
    with tempfile.TemporaryDirectory() as tmp, resources.as_file(src) as src_dir:
        shutil.copytree(src_dir, tmp, dirs_exist_ok=True)
        _docker("build", "--target", target, "-t", ref, tmp, timeout=3600, check=True)
    return ref


def docker_run_argv(
    image: str, name: str, ext_dir: Path, seconds: int, allow_network: bool
) -> list[str]:
    argv = [
        "docker", "run", "--rm", "--name", name,
        "--read-only",
        "--tmpfs", "/tmp:rw,exec,nosuid,size=512m",  # noqa: S108  # nosec B108 - path inside the container
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--pids-limit", "512",
        "--memory", "1g",
        "--cpus", "2",
        "--shm-size", "256m",
        "--mount", f"type=bind,src={ext_dir},dst=/ext,readonly",
    ]  # fmt: skip
    if not allow_network:
        argv += ["--network", "none"]
    return [
        *argv,
        image,
        "--ext=/ext",
        f"--seconds={seconds}",
        *(["--allow-network"] if allow_network else []),
    ]


def run_dynamic(
    ext_dir: Path,
    *,
    manifest_version: int,
    browser: str = "chrome",
    seconds: int = 45,
    allow_network: bool = False,
) -> dict:
    """Run the extension in the sandbox and return validated observations."""
    ext_dir = Path(ext_dir).resolve()
    if any(c in str(ext_dir) for c in (",", "\n")):
        raise DynamicUnavailable("Extension path contains unsupported characters")
    seconds = max(10, min(int(seconds), 300))
    require_docker()
    image = resolve_image(pick_target(browser, manifest_version))
    name = f"extanalyze-{uuid.uuid4().hex[:12]}"
    argv = docker_run_argv(image, name, ext_dir, seconds, allow_network)
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
            argv, capture_output=True, text=True, timeout=seconds + 90, check=False
        )
    except subprocess.TimeoutExpired as e:
        _docker("kill", name)
        raise InvalidDriverOutput("sandbox run timed out") from e
    out = proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else ""
    if len(out.encode()) > MAX_OUTPUT_BYTES:
        raise InvalidDriverOutput("sandbox output too large")
    try:
        raw = json.loads(out)
    except json.JSONDecodeError as e:
        raise InvalidDriverOutput(f"sandbox returned no result (exit {proc.returncode})") from e
    return validate(raw)
