"""Bootstraps a local AntiFl0ck checkout and drives its Docker Compose stack.

Zero runtime dependencies by design: this only shells out to git, node, and
docker, all of which the underlying stack already requires.
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path

from antiflock import __version__

REPO_URL = "https://github.com/AetherAI3/AntiFlock.git"
DEFAULT_REF = "main"
DEFAULT_DIR = "antiflock"
REF_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$")
COMPOSE_ACTIONS = {"dev", "down", "lab", "build", "clean"}

NEXT_STEPS = """
Next steps:
  antiflock dev   Build and start Core, the simulator, and the dashboard
  antiflock lab   Run the one-shot coffee-shop simulation against a running stack

Once running, open http://127.0.0.1:4173 -- username `operator`, token is
ANTIFLOCK_OPERATOR_TOKEN in the config file above. Never commit that file.

Feature/config knobs live in configs/demo.yaml and docker-compose.yml
(profiles, ports, demo-mode flags); full guide: docs/operator-runbook.md
in the checkout.
"""


def is_checkout(directory: Path) -> bool:
    return (directory / "docker-compose.yml").is_file() and (
        directory / "scripts" / "compose.mjs"
    ).is_file()


def require_tool(name: str) -> None:
    if shutil.which(name) is None:
        print(f"{name} is required. Install it, then re-run.", file=sys.stderr)
        raise SystemExit(1)


def ensure_checkout(target: Path, ref: str) -> None:
    if is_checkout(target):
        return

    if target.exists() and any(target.iterdir()):
        print(
            f"{target} already exists and is not an AntiFlock checkout. "
            "Pick an empty directory with --dir, or remove it first.",
            file=sys.stderr,
        )
        raise SystemExit(1)
    if not REF_PATTERN.match(ref):
        print(f"Invalid --ref value: {ref}", file=sys.stderr)
        raise SystemExit(1)

    require_tool("git")
    target.mkdir(parents=True, exist_ok=True)
    print(f"Cloning AntiFlock ({ref}) into {target} ...", flush=True)
    result = subprocess.run(
        ["git", "clone", "--depth", "1", "--branch", ref, REPO_URL, str(target)]
    )
    if result.returncode != 0:
        print("git clone failed. See output above.", file=sys.stderr)
        raise SystemExit(result.returncode or 1)


def run_init(target: Path) -> None:
    require_tool("node")
    result = subprocess.run(
        ["node", str(Path("scripts", "dev-env.mjs"))], cwd=target
    )
    if result.returncode != 0:
        raise SystemExit(result.returncode)
    print(NEXT_STEPS)


def run_compose(target: Path, action: str) -> None:
    require_tool("node")
    result = subprocess.run(
        ["node", str(Path("scripts", "compose.mjs")), action], cwd=target
    )
    raise SystemExit(result.returncode)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="antiflock",
        description="Bootstrap and run AntiFl0ck locally",
        epilog="Docs: https://github.com/AetherAI3/AntiFlock#readme",
    )
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument(
        "command",
        nargs="?",
        choices=["init", *sorted(COMPOSE_ACTIONS)],
        help="init | dev | lab | build | down | clean",
    )
    parser.add_argument(
        "--dir", default=None, help="checkout location (default ./antiflock)"
    )
    parser.add_argument(
        "--ref", default=DEFAULT_REF, help="git ref to clone (default main)"
    )
    return parser


def resolve_target(args: argparse.Namespace) -> Path:
    if args.dir:
        return Path(args.dir).resolve()
    cwd = Path.cwd()
    if is_checkout(cwd):
        return cwd
    return Path(DEFAULT_DIR).resolve()


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 2

    target = resolve_target(args)
    ensure_checkout(target, args.ref)

    if args.command == "init":
        run_init(target)
        return 0
    run_compose(target, args.command)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
