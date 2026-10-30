"""Explicit local installation and retained foreground owner entrypoint."""
import argparse
import json
import signal
import threading
from pathlib import Path

from .local_installation import Installation, LocalInstallationError, require, document
from .local_host import LocalController, host_lock, request, serve


def stopped_result(result):
    state = result.get('infrastructure', {})
    observed = state.get('observed', {})
    container = observed.get('container')
    return (state.get('phase') == 'stopped' and state.get('leftovers') == []
            and 'container' in observed and (container is None or container.get('running') is False))


def run_host(installation):
    from .local_native import LocalNativeHost
    from .local_services import LocalServices
    from .local_manager_owner import ManagerOwner
    from .local_library import open_library
    stopped = threading.Event()
    previous = {}
    def stop(*_): stopped.set()
    with host_lock(installation) as lock_fd:
        _,config,selected=installation.bootstrap()
        if selected['native'] is not None and selected['native']['version']==3:
            from .local_room_prepare import readmit_document
            readmit_document(config,selected['native'],runtime_plan_for=installation.runtime_plan_for)
        services = LocalServices(lock_fd, runtime_plan_for=installation.runtime_plan_for,
            manager_reference_for=lambda profile:installation.open()[0]['manager'])
        manager = ManagerOwner(installation)
        # The controller owns each running Room's ledger path, so the Library
        # composition reads that exact ledger instead of guessing an instance.
        owner = {'controller': None}
        library = open_library(installation,
            ledger_for=lambda room: owner['controller'].ledger(room))
        controller = LocalController(installation, LocalNativeHost, services=services,
            host_lock_fd=lock_fd, manager=manager, library=library)
        owner['controller'] = controller
        started = False
        try:
            # One Library singleton for the whole installation lifetime, started
            # before any Room binds; absent, unsafe or unqualified configuration
            # fails the host here instead of running without it.
            if library is not None:
                library.start()
                started = True
            for sig in (signal.SIGINT, signal.SIGTERM):
                previous[sig] = signal.signal(sig, stop)
            serve(installation, controller, stopped=stopped.is_set, owner_lock_fd=lock_fd)
        finally:
            failures = []
            try: manager.close()
            except Exception: failures.append('manager')
            if controller.native is not None:
                for room in services.rooms:
                    try:
                        result = controller.native.stop(room)
                        if not stopped_result(result): failures.append('workstation')
                    except Exception: failures.append('workstation')
            if started:
                try: library.stop()
                except Exception: failures.append('library')
            if services.close() is not True: failures.append('hub')
            for sig, handler in previous.items(): signal.signal(sig, handler)
            require(not failures, 'LOCAL_HOST_SHUTDOWN_UNCONFIRMED')
    return {'state':'host-stopped'}


def main(argv=None):
    parser = argparse.ArgumentParser(prog='python -m uas local')
    parser.add_argument('--root', required=True, help='private persistent installation directory')
    commands = parser.add_subparsers(dest='operation', required=True)
    setup = commands.add_parser('setup', help='persist explicit digest-pinned references once')
    setup.add_argument('selection', help='installation selection JSON, no secrets')
    runtime = commands.add_parser('select-runtime', help='select pinned runtime bindings before first Room start')
    runtime.add_argument('--room', required=True)
    runtime.add_argument('reference', help='JSON path/sha256 reference, no secrets')
    manager = commands.add_parser('select-manager', help='select an existing Manager grant while host is stopped')
    manager.add_argument('reference', help='JSON object containing path and sha256, not credentials')
    commands.add_parser('inspect', help='offline inspection without native effects')
    commands.add_parser('serve', help='retain the foreground native owner; requires prepared native host')
    for operation in ('start','status','stop'):
        command = commands.add_parser(operation)
        command.add_argument('--room', required=True)
    args = parser.parse_args(argv)
    try:
        installation = Installation(args.root)
        if args.operation == 'setup':
            with open(args.selection, 'rb') as source: raw = source.read(1048577)
            result = installation.setup(raw)
        elif args.operation == 'select-runtime':
            with open(args.reference, 'rb') as source: reference = document(source.read(1048577))
            result = installation.select_runtime(args.room, reference)
        elif args.operation == 'select-manager':
            with open(args.reference, 'rb') as source: reference = document(source.read(1048577))
            result = installation.select_manager(reference)
        elif args.operation == 'inspect': result = installation.status()
        elif args.operation == 'serve': result = run_host(installation)
        else: result = request(installation, args.operation, args.room)
    except Exception as error:
        # No paths, credentials, subprocess stderr or unbounded error details.
        print(json.dumps({'outcome':'unknown','error':getattr(error,'code','LOCAL_OPERATION_FAILED')}))
        return 3
    print(json.dumps(result, sort_keys=True, indent=2))
    if result.get('outcome') == 'unknown': return 3
    if args.operation == 'stop' and not stopped_result(result.get('result', {})): return 3
    if args.operation == 'start':
        state = result.get('result', {}).get('infrastructure', {})
        if (state.get('phase') != 'running' or state.get('leftovers')
                or result.get('result', {}).get('services', {}).get('hub') != 'ready'): return 3
    return 0
