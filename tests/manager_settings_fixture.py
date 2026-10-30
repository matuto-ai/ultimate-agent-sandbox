"""Browser-only local fixture bridge: actual host/Hub/SettingsOwner, no sockets.

Each invocation uses the same private temporary SQLite owners. Input flags are
fixture-only fault/grant injection, never part of a production host request.
"""
from copy import deepcopy
from pathlib import Path
import json
import sys
from uas import library
from uas.library_settings import SettingsOwner
from uas.manager_library_settings import (FieldNotesLibrarySettingsHost,
    ManagerLibrarySettingsHub, LibrarySettingsContact, canonical)
from uas.ledger import RoomLedger, Origin
from uas.manager_actions import HumanSession
import library_support as support


def invoke(root, packet, scenario='normal'):
    root = Path(root)
    base = support.settings()
    owner = SettingsOwner(root/'settings.db', 'installation', lambda:base)
    if not owner.path.exists(): owner.initialize({k:deepcopy(base[k]) for k in ('limits','filters')})
    allowed = scenario != 'project-only'
    connected = scenario != 'revoked'
    principal = library.LocalHuman('human','actor','grant-1',
        lambda _,project,action:allowed and project is None and action == library.SETTINGS_CAPABILITY,
        lambda:connected)
    session = HumanSession('installation','room','instance','human',
        Origin('actor','human','inc','grant',()),lambda _,action:True,lambda:True)
    with RoomLedger(root/'hub.db','room') as ledger:
        contact = LibrarySettingsContact(owner,lambda _:principal)
        def fault(*args,**kwargs):
            if scenario == 'lost-before': raise OSError('private failure')
            result=contact(*args,**kwargs)
            if scenario == 'lost-after': raise OSError('private failure')
            return result
        hub=ManagerLibrarySettingsHub(ledger,deployment_id='installation',room_id='room',instance_id='instance',contact=fault)
        context=object()
        host=FieldNotesLibrarySettingsHost(hub,lambda supplied:session if supplied is context else None)
        if scenario == 'stale':
            observed=owner.handle(canonical(dict(version=1,action='settings-observe',deployment='installation')),principal)
            observed['shared']['limits']['coalesce_seconds']+=1
            owner.handle(canonical(dict(version=1,action='settings-update',deployment='installation',
                request_id='external-'+packet['operation_id'],configuration_version=observed['configuration_version'],
                settings_id=observed['settings_id'],shared=observed['shared'])),principal)
        return host.handle(canonical(packet),context)


if __name__ == '__main__':
    value=json.load(sys.stdin)
    print(json.dumps(invoke(sys.argv[1],value['packet'],value.get('scenario','normal'))))
