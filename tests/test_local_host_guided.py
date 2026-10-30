"""Guided selections are metadata only; host observers are controlled."""
from copy import deepcopy
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch
from uas import local_host_guided as g
from uas.local_host_profile import HostProfileError,LocalHostProfile
from tests.test_local_host_plan import observation,profile

ID='a'*32


def observed():
    value=observation();value['storage']['path']='/var/lib';value['engine']=None;value['subuid']=value['subgid']=[];return value


def exclusive():return {'blockers':[],'accounts':{'passwd':[],'group':[]}}


class GuidedTests(unittest.TestCase):
    def inspect(self,value=None):
        with patch.object(g,'inspect',return_value=observed() if value is None else value),patch.object(g,'inspect_exclusive',return_value=exclusive()):
            return g.inspect_host('/var/lib',ID)
    def config(self):return json.loads((Path(__file__).parent/'fixtures/two-rooms.json').read_text())
    def test_inspection_needs_no_project_or_images(self):
        result=self.inspect();self.assertFalse(result['blockers']);self.assertEqual(result['profile']['mode'],'owned')
        self.assertEqual(result['defaults']['account_uid'],999);self.assertEqual(result['profile']['mapping']['offset'],1048576)
        self.assertIn(ID[:16],result['defaults']['storage_root']);self.assertEqual(result,self.inspect())
    def test_ids_avoid_accounts_and_both_subordinate_tables(self):
        o=observed();o['allocated_ids']=[999,998]
        o['subuid']=[{'user':'rootless','offset':1048576,'size':65536}]
        o['subgid']=[{'user':'other','offset':1114112,'size':65536}]
        result=self.inspect(o);self.assertEqual(result['defaults']['account_uid'],997)
        self.assertEqual(result['profile']['mapping']['offset'],1179648)
    def test_foreign_firstengine_and_existing_paths_are_blockers(self):
        o=observed();o['occupied_paths']=['/var/lib/foreign']
        with patch.object(g,'inspect',return_value=o),patch.object(g,'inspect_exclusive',return_value={**exclusive(),'blockers':['ENGINE_FOREIGN_PROCESS']}):
            result=g.inspect_host('/var/lib',ID)
        self.assertIn('ENGINE_FOREIGN_PROCESS',result['blockers']);self.assertIn('GUIDED_OWNED_PATH_OCCUPIED',result['blockers'])
    def test_existing_engine_unknown_mapping_is_not_reconfigured(self):
        o=observation();o['engine']['docker_root']='/different/root'
        with patch.object(g,'inspect',return_value=o),patch.object(g,'inspect_exclusive') as owned:
            result=g.inspect_host('/var/lib',ID)
        self.assertIsNone(result['profile']);self.assertEqual(result['blockers'],['GUIDED_EXISTING_MAPPING_UNKNOWN']);owned.assert_not_called()
    def test_compatible_existing_engine_uses_verified_mapping_and_defaults(self):
        o=observation()
        daemon={'exe':'/usr/bin/dockerd','uid':[0]*4,'netns':'net:[1]','arguments':{}}
        with patch.object(g,'inspect',return_value=o),patch.object(g,'_processes',return_value=[daemon]),patch.object(g.os,'readlink',side_effect=lambda p: 'net:[1]' if p=='/proc/self/ns/net' else '/run'),patch.object(g.os.path,'realpath',side_effect=lambda p:p.replace('/var/run/','/run/')),patch.object(g.os.path,'lexists',return_value=False),patch.object(g,'inspect_exclusive') as owned:
            result=g.inspect_host('/var/lib',ID)
        self.assertFalse(result['blockers']);self.assertEqual(result['profile']['mode'],'reuse');self.assertEqual(result['profile']['mapping']['offset'],100000);owned.assert_not_called()
    def test_custom_socket_without_configuration_proof_is_blocked(self):
        o=observation();daemon={'exe':'/usr/bin/dockerd','uid':[0]*4,'netns':'net:[1]','arguments':{}}
        with patch.object(g,'inspect',return_value=o),patch.object(g,'_processes',return_value=[daemon]),patch.object(g.os,'readlink',side_effect=lambda p: 'net:[1]' if p=='/proc/self/ns/net' else '/run'),patch.object(g.os.path,'lexists',return_value=False):
            result=g.inspect_host('/var/lib',ID,engine_socket='/run/custom.sock')
        self.assertEqual(result['blockers'],['GUIDED_ENGINE_SOCKET_UNPROVEN'])
    def test_room_choices_preserve_agent_model_credentials_and_repository(self):
        result=self.inspect();original=self.config()
        with patch.object(g,'observe_quotas',return_value={'blocks':{},'inodes':{}}):chosen=g.select_rooms(original,result)
        self.assertFalse(chosen['blockers'])
        for key in ('actors','providers','credentials','manager','images'):self.assertEqual(chosen['config']['deployment'][key],original['deployment'][key])
        for before,after in zip(original['rooms'],chosen['config']['rooms']):
            self.assertEqual(before['seats'],after['seats']);self.assertEqual(before['project']['repository'],after['project']['repository'])
            self.assertTrue(after['state_root'].startswith(result['defaults']['storage_root']+'/'))
        values=list(chosen['settings']['rooms'].values());self.assertNotEqual(values[0]['quota_project_id'],values[1]['quota_project_id']);self.assertNotEqual(values[0]['subnet'],values[1]['subnet'])
    def test_nonxfs_requires_explicit_budget_and_plan_keeps_bound(self):
        o=observed();o['storage'].update(filesystem='btrfs',project_accounting=False,project_enforcement=False)
        inspection=self.inspect(o)
        with self.assertRaisesRegex(HostProfileError,'STORAGE_BUDGET'):g.select_rooms(self.config(),inspection)
        result=g.select_rooms(self.config(),inspection,1024**3)
        self.assertEqual(result['allocation_bytes'],1024**3)
        self.assertEqual(result['host_plan']['operations'][-2]['kind'],'prepare-owned-xfs-file')
    def test_existing_inventory_mcs_routes_and_quota_candidates_are_avoided(self):
        inspection=self.inspect();inspection['profile']=profile();inspection['host_observed']=observation();inspection['host_observed']['storage']['path']='/var/lib'
        with patch.object(g,'observed_engine_allocations',return_value={'levels':{'s0:c0.c3'},'networks':{'172.16.0.0/16'}}),patch.object(g,'observe_quotas',side_effect=lambda _,n:{'blocks':{},'inodes':{}}):
            result=g.select_rooms(self.config(),inspection)
        first=result['settings']['rooms']['alpha'];self.assertEqual(first['mcs_level'],'s0:c4,c5');self.assertEqual(first['subnet'],'172.17.0.0/24')
    def test_blocked_inspection_never_probes_room_resources(self):
        result=self.inspect();result['blockers']=['foreign']
        with patch.object(g,'observe_quotas') as quota,self.assertRaisesRegex(HostProfileError,'HOST_BLOCKED'):g.select_rooms(self.config(),result)
        quota.assert_not_called()

    def test_generated_raw_config_reloads_and_assembles_canonical_profile(self):
        from io import StringIO
        from uas.config import load
        from uas.local_prepare import assemble
        from tests.test_local_native import selections
        inspection=self.inspect()
        with patch.object(g,'observe_quotas',return_value={'blocks':{},'inodes':{}}):
            chosen=g.select_rooms(self.config(),inspection)
        config=load(StringIO(json.dumps(chosen['config'])))
        _,sample=selections();images=sample['rooms']['room']
        identities={}
        def observe(path):
            if path not in identities:identities[path]=[8,len(identities)+1]
            return identities[path]
        native=assemble(config,chosen['settings'],images['workstation'],images['hub'],observe=observe)
        self.assertEqual(native['mapping']['offset'],1048576)
        self.assertEqual(native['rooms']['alpha']['quota_project_id'],chosen['settings']['rooms']['alpha']['quota_project_id'])

    def test_busy_quota_candidate_is_not_selected(self):
        inspection=self.inspect();seen=[]
        def quotas(_,candidate):
            seen.append(candidate)
            return {'blocks':{candidate:{}} if len(seen)==1 else {},'inodes':{}}
        with patch.object(g,'observe_quotas',side_effect=quotas):
            result=g.select_rooms(self.config(),inspection)
        self.assertNotEqual(result['settings']['rooms']['alpha']['quota_project_id'],seen[0])

    def test_custom_engine_paths_require_actual_configuration_evidence(self):
        from types import SimpleNamespace
        o=observation();o['engine']['docker_root']='/srv/engine/100000.100000'
        daemon={'exe':'/usr/bin/dockerd','uid':[0]*4,'netns':'net:[1]',
                'arguments':{'--config-file':'/etc/docker/owned.json'}}
        config=json.dumps({'hosts':['unix:///run/custom.sock'],'data-root':'/srv/engine','exec-root':'/run/custom-engine'}).encode()
        with patch.object(g,'inspect',return_value=o),patch.object(g,'_processes',return_value=[daemon]),patch.object(g.os,'readlink',return_value='net:[1]'),patch.object(g.os.path,'realpath',side_effect=lambda p:p),patch.object(g.os.path,'lexists',return_value=True),patch.object(g,'canonical_node'),patch.object(g.Path,'lstat',return_value=SimpleNamespace(st_uid=0,st_mode=0o100600)),patch('uas.local_prepare.read_file',return_value=config):
            result=g.inspect_host('/var/lib',ID,engine_socket='/run/custom.sock')
        self.assertFalse(result['blockers'])
        self.assertEqual(result['profile']['engine']['exec_root'],'/run/custom-engine')
        self.assertEqual(result['profile']['engine']['data_root'],'/srv/engine')
