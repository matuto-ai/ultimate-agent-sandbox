"""Run `python -m uas validate-config FILE` for offline configuration admission."""
import argparse
import json
import sys

from .config import ConfigError, load
from .launch import check_launch
from .lifecycle import LifecycleError, BackendUnknown, OwnershipConflict


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python -m uas")
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate-config", help="validate without starting processes or contacting providers")
    validate.add_argument("file", help="UTF-8 JSON configuration, or - for stdin")
    validate.add_argument("--available-credential", action="append", default=[], metavar="ID", help="observed available credential reference (not a secret or authentication proof)")
    preflight = commands.add_parser("check-launch", help="read-only launch observations; production launch remains disabled")
    preflight.add_argument("file", help="UTF-8 JSON configuration, or - for stdin")
    preflight.add_argument("--room", required=True)
    preflight.add_argument("--broker-socket", help="narrow Room control-store socket to inspect, never connect")
    preflight.add_argument("--broker-uid", type=int, help="expected non-root owner from trusted supervisor policy")
    preflight.add_argument("--broker-gid", type=int, help="expected non-root group from trusted supervisor policy")
    native = commands.add_parser('qualify-native', help='check explicit native qualification inputs; not production startup')
    native.add_argument('file', help='UTF-8 project configuration')
    native.add_argument('--installation', required=True, help='private immutable installation-reference JSON')
    native.add_argument('--installation-sha256', required=True, help='independently selected exact installation digest')
    native.add_argument('--execute-qualification', action='store_true', help='explicit disposable qualification only')
    args = parser.parse_args(argv)
    def inspect(source):
        if args.command == 'qualify-native':
            from .native_qualification import QualificationPlan, QualificationError
            plan = QualificationPlan.read(source.read(1048577), args.installation, args.installation_sha256)
            if args.execute_qualification:
                from .native_qualification import execute
                return execute(plan)
            return plan.preflight()
        if args.command == "check-launch":
            return check_launch(source, args.room, broker_socket=args.broker_socket,
                                broker_uid=args.broker_uid, broker_gid=args.broker_gid)
        return load(source, available_credentials=args.available_credential)
    try:
        if args.file == "-":
            result = inspect(sys.stdin)
        else:
            with open(args.file, encoding="utf-8") as source:
                result = inspect(source)
    except ConfigError as error:
        print(json.dumps({"error": "INVALID_CONFIG", "field": error.field, "reason": error.reason}), file=sys.stderr)
        return 2
    except (OSError, UnicodeError):
        print(json.dumps({"error": "CONFIG_UNREADABLE", "field": "$", "reason": "cannot read UTF-8 configuration"}), file=sys.stderr)
        return 2
    except ValueError as error:
        from .native_qualification import QualificationError
        if not isinstance(error, QualificationError): raise
        print(json.dumps({'error': error.code, 'production_launcher': 'disabled'}), file=sys.stderr)
        return 3
    except (LifecycleError, BackendUnknown, OwnershipConflict) as error:
        print(json.dumps({'error': getattr(error, 'code', type(error).__name__),
                          'production_launcher': 'disabled'}), file=sys.stderr)
        return 3
    print(json.dumps(result, sort_keys=True, indent=2))
    return 3 if args.command == 'check-launch' or args.command == 'qualify-native' and not args.execute_qualification else 0


if __name__ == "__main__":
    raise SystemExit(main())
