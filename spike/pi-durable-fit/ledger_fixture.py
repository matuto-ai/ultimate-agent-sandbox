"""Test-only host around the unchanged RoomLedger, not a production Run reducer.

The input is a trusted local test driver's request. Its `authorized` switch
injects a host authorization failure; it is never an event-supplied identity.
"""
import json
from pathlib import Path
import sys

SOURCE = Path(__file__).resolve().parents[2]
if not (SOURCE / 'uas' / 'ledger.py').is_file():
    raise RuntimeError('Run this fixture from the repository spike/pi-durable-fit layout')
sys.path.insert(0, str(SOURCE))
from uas.ledger import Command, Event, LedgerError, Origin, RoomLedger, Transition

request = json.load(sys.stdin)
origin = Origin('fixture-human', 'fixture-participant', 'fixture-process',
                'fixture-policy-v1', ('fixture-work',))
with RoomLedger(sys.argv[1], 'fixture-room') as ledger:
    try:
        if request['action'] == 'snapshot':
            result = ledger.snapshot()
        else:
            operation = Command(**request['command'])

            def authorize(who, command):
                state = ledger.snapshot()['state']
                return (request.get('authorized', True) is True and
                        who == origin and
                        (command.kind in ('fixture.fence', 'fixture.enable') or
                         state.get('enabled', True)))

            def decide(state, command):
                if command.target != 'fixture-project':
                    raise LedgerError('OUT_OF_SCOPE')
                generation = state.get('generation', 0)
                if command.generation != generation:
                    raise LedgerError('STALE_GENERATION')
                if command.kind == 'fixture.admit':
                    if set(command.payload) != {'event_id', 'project', 'text'}:
                        raise LedgerError('INVALID_PAYLOAD')
                    if command.payload['project'] != 'fixture-project':
                        raise LedgerError('OUT_OF_SCOPE')
                    # Test-only single-event intake policy. Pi does not provide
                    # source-event identity or canonical payload conflict checks.
                    previous = state.get('event')
                    admission = state.get('admission', {})
                    if (previous and previous['event_id'] == command.payload['event_id']
                            and admission.get('generation') == generation):
                        if previous != command.payload:
                            raise LedgerError('EVENT_CONFLICT')
                        return Transition(state, (Event('fixture.redelivery', admission),), admission)
                    request_id = f"fixture-room:g{generation}:{command.id}"
                    result = {'request_id': request_id, 'generation': generation}
                    state = {**state, 'enabled': True, 'generation': generation,
                             'admission': result, 'event': command.payload}
                elif command.kind in ('fixture.fence', 'fixture.enable'):
                    if command.payload:
                        raise LedgerError('INVALID_PAYLOAD')
                    state = {**state, 'enabled': command.kind == 'fixture.enable',
                             'generation': generation + 1}
                    result = {'generation': generation + 1, 'enabled': state['enabled']}
                elif command.kind == 'fixture.bind':
                    if set(command.payload) != {'conversation_id', 'submission_id'}:
                        raise LedgerError('INVALID_PAYLOAD')
                    state = {**state, 'execution': command.payload}
                    result = command.payload
                else:
                    raise LedgerError('UNKNOWN_COMMAND')
                return Transition(state, (Event(command.kind, result),), result)

            result = ledger.apply(operation, origin, authorize=authorize, decide=decide)
        print(json.dumps({'ok': True, 'result': result}))
    except LedgerError as error:
        print(json.dumps({'ok': False, 'error': error.code}))
