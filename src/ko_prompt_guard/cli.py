"""Content-minimizing command-line interface for prompt checks."""
from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .guard import Guard
from .policy import GuardPolicy
from .result import Verdict


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ko-prompt-guard")
    parser.add_argument("mode", choices=("check", "context", "messages"))
    parser.add_argument("input", nargs="?", default="-", help="file, literal text, or -")
    parser.add_argument("--policy", type=Path, help="GuardPolicy JSON file")
    parser.add_argument("--source", default="context", help="context provenance label")
    parser.add_argument("--include-text", action="store_true", help="include local source fields")
    parser.add_argument("--pretty", action="store_true")
    parser.add_argument("--version", action="version", version=f"ko-prompt-guard {__version__}")
    return parser


def _read(value: str) -> str:
    if value == "-":
        return sys.stdin.read()
    path = Path(value)
    return path.read_text("utf-8") if path.is_file() else value


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        policy = (
            GuardPolicy.model_validate_json(args.policy.read_text("utf-8"))
            if args.policy
            else GuardPolicy()
        )
        source = _read(args.input)
    except (OSError, UnicodeError, TypeError, ValueError) as exc:
        parser.error(str(exc))
    guard = Guard(policy)

    try:
        if args.mode == "messages":
            messages = json.loads(source)
            message_result = guard.check_messages(messages)
            payload = (
                message_result.model_dump(mode="json")
                if args.include_text
                else message_result.telemetry().model_dump(mode="json")
            )
            exit_code = 0 if message_result.verdict is Verdict.ALLOW else 2
        elif args.mode == "context":
            context_result = guard.scan_context(source, source=args.source)
            payload = {
                "poisoned": context_result.poisoned,
                "source": context_result.source,
                "recommendation": context_result.recommendation,
                "was_obfuscated": context_result.was_obfuscated,
                "violations": [
                    {
                        "code": item.code,
                        "category": item.category.value,
                        "severity": item.severity.value,
                    }
                    for item in context_result.violations
                ],
            }
            if args.include_text:
                payload["normalized_text"] = context_result.normalized_text
            exit_code = 2 if context_result.poisoned else 0
        else:
            prompt_result = guard.check(source)
            payload = (
                prompt_result.model_dump(mode="json")
                if args.include_text
                else prompt_result.telemetry().model_dump(mode="json")
            )
            exit_code = 0 if prompt_result.verdict is Verdict.ALLOW else 2
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        parser.error(str(exc))

    print(json.dumps(payload, ensure_ascii=False, indent=2 if args.pretty else None))
    return exit_code


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
