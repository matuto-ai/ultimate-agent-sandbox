"""Pure host decisions; these tests never run a host command or privileged apply."""
from copy import deepcopy
import unittest
from unittest.mock import patch

from uas.local_host_profile import HostProfileError, LocalHostProfile, digest
from uas.local_host_plan import plan, verify_plan


def profile(mode='reuse'):
    return {'version': 1, 'profile': 'local-host-v1', 'installation_id': 'a'*32,
            'mode': mode, 'engine': {'version': '29.8.2', 'socket': '/run/docker.sock',
                                    'data_root': '/var/lib/docker', 'exec_root': '/run/docker'},
            'mapping': {'user': 'uas-remap', 'offset': 100000, 'size': 65536}}


def observation():
    row = profile()['mapping']
    return {'version': 1, 'selinux': 'Enforcing', 'engine': {
        'version': '29.8.2', 'docker_root': '/var/lib/docker/100000.100000',
        'security_options': ['name=seccomp,profile=builtin', 'name=selinux', 'name=userns'],
        'socket_identity': [1, 22]}, 'subuid': [deepcopy(row)], 'subgid': [deepcopy(row)],
        'allocated_ids': [0, 1000], 'storage': {'path': '/srv', 'identity': [2, 30],
        'filesystem': 'xfs', 'project_accounting': True, 'project_enforcement': True,
        'free_bytes': 8*1024**3, 'owner_uid': 0, 'mode': 0o755},
        'occupied_paths': [], 'networks': ['192.168.1.0/24']}


def selected(p=None, o=None, **kwargs):
    return plan(p or profile(), o or observation(), storage_root='/srv/uas-local',
                endpoints_root='/run/uas-local', **kwargs)


class LocalHostPlanTests(unittest.TestCase):
    def test_no_effect_and_inputs_preserved(self):
        p, o = profile(), observation()
        before = deepcopy((p, o))
        with (patch('subprocess.run', side_effect=AssertionError('process forbidden')),
              patch('builtins.open', side_effect=AssertionError('file forbidden'))):
            result = selected(p, o)
        self.assertEqual((p, o), before)
        self.assertEqual(result['status'], 'planned')
        self.assertEqual(verify_plan(result, o), result)
        self.assertEqual([x['kind'] for x in result['operations']],
                         ['prepare-owned-xfs-tree', 'prepare-owned-endpoints'])

    def test_default_translations_preserved(self):
        p = LocalHostProfile.parse(profile())
        self.assertEqual(p.owners, {'gate': 165530, 'hub': 165531, 'runtime': 165532,
                                    'supervisor': 165533, 'broker': 165534})
        self.assertEqual(p.docker_root, '/var/lib/docker/100000.100000')
        self.assertEqual(p.document(), profile())

    def test_mapping_is_one_translation(self):
        doc = profile(); doc['mapping']['offset'] = 500000
        p = LocalHostProfile.parse(doc)
        self.assertEqual(p.owners['supervisor'], 565533)
        self.assertEqual(p.docker_root, '/var/lib/docker/500000.500000')
        for bad in (-1, True, 65536):
            with self.assertRaises(HostProfileError): p.host_id(bad)

    def test_selected_engine_never_ambient(self):
        p = LocalHostProfile.parse(profile())
        self.assertEqual(p.docker_argv(['info']), ['/usr/bin/docker', '--host', 'unix:///run/docker.sock', 'info'])
        self.assertNotIn('DOCKER_HOST', p.environment())
        self.assertEqual(p.environment()['DOCKER_CONFIG'], '/nonexistent')

    def test_changed_engine_fails(self):
        for field, value in [('version', '29.9'), ('docker_root', '/var/lib/other'),
                             ('security_options', ['name=userns'])]:
            o = observation(); o['engine'][field] = value
            with self.assertRaises(HostProfileError): selected(o=o)

    def test_stale_plan_rejects_any_changed_identity(self):
        value = selected()
        o = observation(); o['storage']['identity'] = [2, 31]
        with self.assertRaisesRegex(HostProfileError, 'HOST_PLAN_STALE'): verify_plan(value, o)
        o = observation(); o['storage']['free_bytes'] -= 4096
        self.assertEqual(verify_plan(value, o), value)

    def test_storage_observation_must_name_immediate_parent(self):
        with self.assertRaisesRegex(HostProfileError, 'HOST_STORAGE_PARENT'):
            plan(profile(), observation(), storage_root='/srv/nested/uas-local',
                 endpoints_root='/run/uas-local')

    def test_forged_rehashed_plan_rejected(self):
        value = selected(); value['operations'] = []
        value['plan_id'] = digest({k:v for k,v in value.items() if k != 'plan_id'})
        with self.assertRaisesRegex(HostProfileError, 'HOST_PLAN_SEMANTICS'):
            verify_plan(value, observation())

    def test_collisions_block_without_mutation(self):
        for key in ('subuid', 'subgid'):
            o = observation(); o[key].append({'user':'human', 'offset':120000, 'size':65536})
            self.assertIn(key.upper()+'_COLLISION', selected(o=o)['blockers'])
        o = observation(); o['allocated_ids'].append(165532)
        self.assertIn('HOST_ID_COLLISION', selected(o=o)['blockers'])
        o = observation(); o['occupied_paths'].append('/srv/uas-local')
        self.assertIn('OWNERSHIP_RECONCILIATION_REQUIRED', selected(o=o)['blockers'])

    def test_existing_daemon_is_not_reconfigured(self):
        o = observation(); o['subuid'] = []
        self.assertIn('REUSE_REQUIRES_EXISTING_MAPPING', selected(o=o)['blockers'])
        self.assertNotIn('prepare-owned-engine', [x['kind'] for x in selected(o=o)['operations']])

    def test_owned_engine_cannot_fake_readiness(self):
        value = selected(p=profile('owned'))
        self.assertIn('OWNED_ENGINE_COEXISTENCE_IMPLEMENTATION_REQUIRED', value['blockers'])
        with self.assertRaisesRegex(HostProfileError, 'HOST_PLAN_BLOCKED'):
            verify_plan(value, observation())

    def test_non_xfs_requires_explicit_bounded_selection(self):
        o = observation(); o['storage']['filesystem'] = 'btrfs'
        self.assertIn('OWNED_XFS_ALLOCATION_SELECTION_REQUIRED', selected(o=o)['blockers'])
        value = selected(o=o, allocation_bytes=1024**3)
        operation = next(x for x in value['operations'] if x['kind'] == 'prepare-owned-xfs-file')
        self.assertEqual(operation['bytes'], 1024**3)
        self.assertFalse(operation['format_existing_device'])
        self.assertEqual(verify_plan(value, o), value)
        for size in (-1, True, 1, 1024**4+1024):
            with self.assertRaises(HostProfileError): selected(o=o, allocation_bytes=size)
        self.assertIn('OWNED_XFS_ALLOCATION_SPACE', selected(o=o, allocation_bytes=9*1024**3)['blockers'])

    def test_no_automatic_selinux_downgrade_or_fix(self):
        o = observation(); o['selinux'] = 'Permissive'
        value = selected(o=o)
        self.assertIn('SELINUX_ENFORCING_REQUIRED', value['blockers'])
        self.assertFalse(any('selinux' in x['kind'] for x in value['operations']))

    def test_paths_and_schema_strict(self):
        for path in ('/srv/../etc', '/srv//uas', '/', '/srv/space here', '/srv/uas\n'):
            p=profile(); p['engine']['socket']=path
            with self.assertRaises(HostProfileError): LocalHostProfile.parse(p)
        p=profile();p['extra']=1
        with self.assertRaises(HostProfileError): LocalHostProfile.parse(p)

    def test_preparation_roots_never_overlap_engine_paths(self):
        # In particular, a nonexistent child of Docker's data directory is not
        # free installation space merely because occupied_paths is empty.
        o = observation(); o['storage']['path'] = '/var/lib'
        with self.assertRaisesRegex(HostProfileError, 'HOST_ENGINE_ROOT_OVERLAP'):
            plan(profile(), o, storage_root='/var/lib/docker/uas-new', endpoints_root='/run/uas-local')
        for engine in ('/var/lib/docker', '/run/docker', '/run/docker.sock'):
            for root in (engine, engine + '/uas-new', str(__import__('pathlib').PurePosixPath(engine).parent)):
                o = observation(); o['storage']['path'] = '/srv'
                with self.assertRaisesRegex(HostProfileError, 'HOST_(ENGINE_)?ROOT_OVERLAP'):
                    plan(profile(), o, storage_root='/srv/uas-local', endpoints_root=root)


if __name__ == '__main__':
    unittest.main()
