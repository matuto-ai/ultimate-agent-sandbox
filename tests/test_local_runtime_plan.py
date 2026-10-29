"""Finite metadata-only local runtime plan checks, no runtime or credentials."""
from copy import deepcopy
from io import StringIO
import hashlib
import json
import unittest
from unittest.mock import patch
from uas.config import load
from uas.local_native import LocalNativeProfile
from uas.local_runtime_plan import LocalRuntimePlan
from uas.native_qualification import QualificationError, QualificationPlan
from uas.native_image_package import payload, canonical, inventory
import test_native_qualification as qualification_fixture
from test_local_installation import native_selection


class LocalRuntimePlanTests(unittest.TestCase):
    def setUp(self):
        source=qualification_fixture.NativeQualificationTests();source.setUp()
        self.input_config=source.config;self.config=load(StringIO(json.dumps(source.config)));self.doc=native_selection(self.config)
        for row in self.doc['rooms'].values():
            row['workstation']['image_reference']=row['workstation']['image_id']
        self.native=LocalNativeProfile(self.config,self.doc,'alpha',self.config['deployment']['state_root'])
        self.selection={'version':1,'profile':'local-runtime-v1','room_id':'alpha','installation_id':self.native.nonce,
            'human_mergers':[7],**{k+'_manifest':{'path':'/installation/'+k+'.json','sha256':'a'*64}
                                for k in ('pi','claude','broker')}}
        self.manifests={}
        for runtime in ('pi','claude'):
            baked=payload(runtime,dict.fromkeys(inventory(runtime),'d'*64))
            self.manifests[runtime]={**baked,'image_id':self.native.image_id,'image_reference':self.native.image_reference,
                                    'payload_manifest_digest':hashlib.sha256(canonical(baked)).hexdigest()}
        self.broker={'version':1,'credential_path':'/private/forge.json','gh_executable':'/usr/bin/gh',
                     'gh_sha256':'e'*64,'gate_actor':self.config['deployment']['actors'][0]['id'],
                     'review_actor':self.config['deployment']['actors'][1]['id']}
    def plan(self):
        return LocalRuntimePlan(json.dumps(self.input_config),self.selection,installation_digest='f'*64,native_profile=self.native)
    def test_local_endpoint_tree_cannot_be_a_credential_source(self):
        from uas.native_qualification import broker_selection,credential_excluded_roots
        plan=self.plan();broker={**self.broker,'credential_path':str(self.native.endpoints/'private-key')}
        self.assertIn(str(self.native.endpoints),credential_excluded_roots(plan))
        with patch('uas.native_qualification.read_manifest',return_value=broker):
            with self.assertRaisesRegex(QualificationError,'CREDENTIAL_INSIDE'):
                broker_selection(plan)

    def test_distinct_plan_canonical_digest_and_finite_operation_not_host_deadline(self):
        plan=self.plan();self.assertIsNot(type(plan),QualificationPlan)
        self.assertEqual(plan.config_digest,self.native.config_digest)
        self.assertEqual(plan.operation_timeout_seconds,180)
        self.assertNotIn('nonce',plan.installation);self.assertNotIn('timeout_seconds',plan.installation)
        self.assertEqual(plan.review_configuration()['human_mergers'],[7])
    def test_disposable_fields_implicit_grants_and_bad_budgets_refused(self):
        for key,value in [('nonce','a'*32),('human_host_manifest',{}),('timeout_seconds',180),
                          ('operation_timeout_seconds',181),('operation_timeout_seconds',True),
                          ('operation_timeout_seconds',0),('token','secret'),('profile','disposable-native-v1')]:
            old=deepcopy(self.selection);self.selection[key]=value
            with self.subTest(key=key,value=value),self.assertRaises(QualificationError):self.plan()
            self.selection=old
    def test_resource_pairs_and_reference_shapes(self):
        for extras in ({'git_manifest':{'path':'/x','sha256':'a'*64}},
                       {'gate_manifest':{'path':'/x','sha256':'a'*64}},
                       {'pi_manifest':{'path':'relative','sha256':'a'*64}},
                       {'pi_manifest':{'path':'/x','sha256':'a'*64,'token':'secret'}}):
            old=deepcopy(self.selection);self.selection.update(extras)
            with self.assertRaises(QualificationError):self.plan()
            self.selection=old
    def test_exact_room_installation_and_native_config_binding(self):
        for key,value in [('room_id','beta'),('installation_id','0'*32)]:
            old=deepcopy(self.selection);self.selection[key]=value
            with self.assertRaises(QualificationError):self.plan()
            self.selection=old
        self.input_config['rooms'][0]['resources']['pids']+=1
        with self.assertRaises(QualificationError):self.plan()
    def test_mutated_declarations_fail_before_manifest_read(self):
        for mutation in ('configuration','selection','text'):
            plan=self.plan()
            if mutation=='configuration':plan.config['rooms'][0]['resources']['pids']+=1
            elif mutation=='selection':plan.installation['human_mergers']=[9]
            else:plan.config_text+=' '
            with patch('uas.local_runtime_plan.read_manifest') as read,self.assertRaises(QualificationError):plan.check()
            read.assert_not_called()
    def test_check_uses_exact_archive_payload_and_broker_metadata_only(self):
        def read(filename,digest):return deepcopy(self.manifests['pi' if filename.endswith('pi.json') else 'claude'])
        with patch('uas.local_runtime_plan.read_manifest',side_effect=read) as reader,\
             patch('uas.native_qualification.read_manifest',return_value=self.broker) as broker:
            result=self.plan().check()
        self.assertFalse(result['effects']);self.assertEqual(result['missing_prerequisites'],[])
        self.assertEqual(reader.call_count,2);broker.assert_called_once_with('/installation/broker.json','a'*64)
        self.assertIn('authenticated-human-session',result['unobserved'])
    def test_wrong_image_or_payload_reports_missing_not_authority(self):
        for key,value in [('image_id','sha256:'+'0'*64),('runtime_version','wrong'),('payload_manifest_digest','0'*64)]:
            broken=deepcopy(self.manifests['pi']);broken[key]=value
            with patch('uas.local_runtime_plan.read_manifest',return_value=broken),\
                 patch('uas.native_qualification.read_manifest',return_value=self.broker):result=self.plan().check()
            self.assertIn('PI_IMAGE_MANIFEST_UNAVAILABLE',result['missing_prerequisites'])
    def test_read_requires_digest_verified_public_descriptor(self):
        with patch('uas.local_runtime_plan.read_manifest',return_value=self.selection) as read:
            result=LocalRuntimePlan.read(json.dumps(self.input_config),'/installation/runtime.json','f'*64,native_profile=self.native)
        read.assert_called_once_with('/installation/runtime.json','f'*64)
        self.assertEqual(result.installation,self.selection)
        with patch('uas.local_runtime_plan.read_manifest',side_effect=ValueError('changed')):
            with self.assertRaises(QualificationError):
                LocalRuntimePlan.read(json.dumps(self.input_config),'/installation/runtime.json','f'*64,native_profile=self.native)

    def test_mutated_operation_seats_or_image_selection_cannot_escape_binding(self):
        for mutation in ('timeout','seats','image'):
            self.setUp();plan=self.plan()
            if mutation=='timeout':plan.operation_timeout_seconds=999
            elif mutation=='seats':plan.seats={}
            else:plan.native_profile.image_reference='image:latest'
            with self.assertRaises(QualificationError):plan.require_unchanged()

    def test_profile_binds_git_gate_exactly_without_modifying_base_declarations(self):
        refs={k+'_manifest':{'path':'/installation/'+k+'.json','sha256':'a'*64} for k in ('git','git_broker','gate')}
        self.selection.update(refs);plan=self.plan();old=self.native.spec()
        with patch('uas.native_git_resources.selection',return_value={'image_id':self.native.image_id}) as git,\
             patch('uas.native_gate_resources.selection',return_value={'image_id':self.native.image_id}) as gate:
            self.native.bind_runtime(plan)
        git.assert_called_once_with(plan);gate.assert_called_once_with(plan)
        self.assertIs(self.native.git_plan,plan);self.assertIs(self.native.gate_plan,plan)
        self.assertNotEqual(old,self.native.spec());plan.require_unchanged()
    def test_bad_git_pairing_fails_before_runtime_binding(self):
        self.selection.update({k+'_manifest':{'path':'/installation/'+k+'.json','sha256':'a'*64} for k in ('git','git_broker')})
        plan=self.plan()
        from uas.lifecycle import LifecycleError
        with patch('uas.native_git_resources.selection',return_value={'image_id':'sha256:'+'0'*64}):
            with self.assertRaises(LifecycleError):self.native.bind_runtime(plan)
        self.assertIsNone(self.native.runtime_plan);self.assertIsNone(self.native.git_plan)
