"""Run `python -m uas validate-config FILE` for offline configuration admission."""
import argparse
import json
import sys

from .config import ConfigError, load


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python -m uas")
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate-config", help="validate without starting processes or contacting providers")
    validate.add_argument("file", help="UTF-8 JSON configuration, or - for stdin")
    validate.add_argument("--available-credential", action="append", default=[], metavar="ID", help="observed available credential reference (not a secret or authentication proof)")
    args = parser.parse_args(argv)
    try:
        if args.file == "-":
            result = load(sys.stdin, available_credentials=args.available_credential)
        else:
            with open(args.file, encoding="utf-8") as source:
                result = load(source, available_credentials=args.available_credential)
    except ConfigError as error:
        print(json.dumps({"error": "INVALID_CONFIG", "field": error.field, "reason": error.reason}), file=sys.stderr)
        return 2
    except (OSError, UnicodeError):
        print(json.dumps({"error": "CONFIG_UNREADABLE", "field": "$", "reason": "cannot read UTF-8 configuration"}), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
