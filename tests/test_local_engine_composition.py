"""Selected-engine wiring through real owners; external process/socket IO doubled.

No Docker daemon, root operation, or native participant is started by this suite.
"""
from contextlib import ExitStack
from io import BytesIO
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from uas import local_services as services, local_hub_host as hub
from uas import native_session as session
from uas.local_native import LocalNativeProfile
from uas.local_native_run_session import LocalNativeRunSession
from uas.native_hub_image import source_inventory
from tests.test_local_native_engine import selections
from tests import test_local_services as service_fixtures


class StopAtBoundary(Exception):
    pass


class EngineCompositionTests(unittest.TestCase):
    def test_parent_startup_reaches_idle_hub_api_on_selected_socket(self):
        config, doc = selections()
        doc['host_profile']['mapping']['offset']=500000
        doc['mapping']['offset']=500000
        p = LocalNativeProfile(config, doc, 'room', '/srv/uas/control')
        fixtures = service_fixtures.LocalServicesTests()
        owner, backend = fixtures.owner(), fixtures.backend()
        p.room['seats']=[{'participant':'alice','actor':'actor-a','profile':'native-pi-v1'},
                         {'participant':'bob','actor':'actor-b','profile':'native-claude-v1'}]
        p.room['project'].update(repository='owner/repository')
        p.room['profiles']=[{'id':name,'capabilities':['forge-read']} for name in ('native-pi-v1','native-claude-v1')]
        backend.profile = p
        process = Mock(); process.poll.return_value = None
        with (patch.object(services.os, 'geteuid', return_value=0),
              patch.object(services, 'mapping_digest', return_value='a'*64),
              patch.object(services.os, 'stat', return_value=SimpleNamespace(st_gid=55)) as stat,
              patch.object(services.subprocess, 'Popen', return_value=process) as spawn,
              patch.object(services, 'read_ready', return_value={'status':'ready'}),
              patch.object(services, 'send_startup') as send):
            owner.ensure('room', Mock(), backend, {'instance_id':'instance'})
        stat.assert_any_call('/run/uas-engine.sock')
        self.assertFalse(any(call.args[0]=='/run/docker.sock' for call in stat.call_args_list))
        self.assertIn(55, spawn.call_args.kwargs['extra_groups'])
        self.assertEqual(spawn.call_args.kwargs['user'],565533)
        self.assertEqual(spawn.call_args.kwargs['group'],565533)
        self.assertTrue({565531} <= set(spawn.call_args.kwargs['extra_groups']))
        raw = send.call_args.args[1].rstrip(b'\n')
        startup = hub.startup_document(raw)
        self.assertEqual(startup['host_profile'], doc['host_profile'])
        self.assertNotIn('runtime', startup)
        api = Mock(); api.socket_path = '/run/uas-engine.sock'
        listener, peer = Mock(), Mock()
        with (patch.object(hub.os, 'getuid', return_value=565533),
              patch.object(hub.os, 'getgid', return_value=565533),
              patch.object(hub, 'probe'), patch.object(hub.os, 'pidfd_open', return_value=42),
              patch.object(hub.os, 'close'), patch.object(hub, '_identity', return_value=(1,2)),
              patch.object(hub.socket, 'socket', side_effect=[listener,peer]),
              patch.object(hub, 'DockerExecAPI', return_value=api) as make_api,
              patch.object(hub, 'start_hub_channel', return_value=(Mock(),Mock(),{'controller':'owned'},None)) as channel,
              patch.object(hub, 'retain') as retain,
              patch.object(hub.sys, 'stdout', SimpleNamespace(buffer=BytesIO()))):
            hub.run(raw, 0)
        make_api.assert_called_once_with('/run/uas-engine.sock')
        self.assertIs(channel.call_args.args[0], api)
        retain.assert_called_once()

    def test_native_participant_path_uses_same_engine_before_first_endpoint_effect(self):
        config, doc = selections()
        doc['host_profile']['mapping']['offset']=500000
        doc['mapping']['offset']=500000
        p = LocalNativeProfile(config, doc, 'room', '/srv/uas/control')
        from uas.local_runtime_plan import LocalRuntimePlan
        plan=LocalRuntimePlan.__new__(LocalRuntimePlan)
        plan.native_profile=p;plan.room=p.room;plan.installation={};plan.operation_timeout_seconds=30
        plan.require_unchanged=Mock()
        host = LocalNativeRunSession.__new__(LocalNativeRunSession)
        host.plan=plan; host.supervisor=Mock()
        resources={'room_id':'room','instance':'instance','supervisor_directory':'/owned', 'peer_path':'/owned/peer'}
        with (patch.object(session.os, 'getuid', return_value=565533),
              patch.object(session.os, 'getgid', return_value=565533),
              patch.object(session.os, 'umask'), patch.object(session, 'probe'),
              patch.object(LocalNativeRunSession, '_require_owner'),
              patch.object(LocalNativeRunSession, 'current'),
              patch.object(LocalNativeRunSession, 'operation_current'),
              patch.object(session, 'DockerExecAPI') as make_api,
              patch.object(session, 'EndpointLease', side_effect=StopAtBoundary)):
            with self.assertRaises(StopAtBoundary):
                session.run(plan, resources, 11, local_host=host)
        make_api.assert_called_once_with('/run/uas-engine.sock')

    def test_hub_image_inventory_binds_selected_engine_dependencies(self):
        root=Path(__file__).resolve().parents[1]
        inventory=source_inventory(root)
        for name in ('local_host_profile.py','local_native.py','local_hub_host.py','native_session.py'):
            self.assertEqual(inventory['/opt/uas/uas/'+name],
                             hashlib.sha256((root/'uas'/name).read_bytes()).hexdigest())
