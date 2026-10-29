"""Public read-only discovery and generated files reach the canonical planner."""
from copy import deepcopy
from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
import unittest
from unittest.mock import patch
from uas import local_setup as setup,local_host_guided as guided
from uas.local_host_profile import HostProfileError,canonical
from tests.test_local_host_guided import observed,exclusive,ID
from tests.test_local_engine_prepare import observation as engine_observation
from tests import test_local_prepare as fixtures

class GuidedSetupTests(unittest.TestCase):
    def setUp(self):
        self.f=fixtures.LocalPrepareTests();self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.observed=observed();self.observed['storage'].update(path=str(self.f.root),identity=[self.f.root.stat().st_dev,self.f.root.stat().st_ino])
        with patch.object(guided,'inspect',return_value=self.observed),patch.object(guided,'inspect_exclusive',return_value=exclusive()):
            self.inspection=guided.inspect_host(str(self.f.root),ID)
        self.project=json.loads(self.f.project_file.read_bytes())
    def propose(self):
        with patch.object(guided,'observe_quotas',return_value={'blocks':{},'inodes':{}}):
            return setup.guided_proposal(self.inspection,project=self.project)
    def test_public_inspect_has_no_project_or_image_dependency(self):
        output=self.f.root/'inspection'
        with patch.object(guided,'inspect_host',return_value=self.inspection),patch.object(setup,'verified_output') as images,redirect_stdout(StringIO()):
            setup.main(['inspect','--output',str(output)])
        images.assert_not_called();self.assertEqual(json.loads((output/'inspection.json').read_bytes()),self.inspection)
    def test_image_independent_existing_project_proposal(self):
        with patch.object(setup,'verified_output') as images:
            value=self.propose()
        images.assert_not_called();self.assertEqual(value['project'],self.project)
        self.assertNotEqual(value['selection']['config']['deployment']['state_root'],self.project['deployment']['state_root'])
    def test_bound_generated_inputs_reach_actual_engine_and_room_planners(self):
        value=self.propose();output=self.f.root/'guided-plan'
        with patch.object(guided,'observe_quotas',return_value={'blocks':{},'inodes':{}}),patch.object(setup,'inspect',return_value=self.observed),patch('uas.local_engine_observe.inspect_exclusive',return_value=engine_observation()):
            result=setup.bind_guided(value,self.f.ws,self.f.hub,self.f.revision,output)
        request=json.loads((output/'request.json').read_bytes())
        self.assertEqual(result['status'],'planned')
        self.assertEqual(request['rooms']['settings']['host_profile']['mapping']['offset'],1048576)
        self.assertEqual(request['engine']['account']['uid'],999)
        self.assertEqual(sorted(request['rooms']['config']['deployment']['providers'],key=lambda p:p['id']),sorted(self.project['deployment']['providers'],key=lambda p:p['id']))
        self.assertEqual(json.loads(self.f.project_file.read_bytes()),self.project)
    def test_tampered_proposal_never_writes_inputs(self):
        value=self.propose();value['allocation_bytes']=123;output=self.f.root/'bad'
        with self.assertRaisesRegex(HostProfileError,'PROPOSAL_CHANGED'):
            setup.bind_guided(value,self.f.ws,self.f.hub,self.f.revision,output)
        self.assertFalse(output.exists());self.assertFalse(output.with_name(output.name+'-inputs').exists())
    def test_existing_image_choice_not_silently_overwritten(self):
        value=self.propose();self.f.write(self.f.project_file,self.project)
        # A genuinely different verified pair cannot override an existing choice.
        value['project']['deployment']['images'][0]['reference']='sha256:'+'f'*64
        value['selection']=None
        from uas.local_host_profile import digest
        value['proposal_id']=digest({k:v for k,v in value.items() if k!='proposal_id'})
        with patch.object(guided,'observe_quotas',return_value={'blocks':{},'inodes':{}}),self.assertRaisesRegex(HostProfileError,'SETUP_SELECTED_IMAGE'):
            setup.bind_guided(value,self.f.ws,self.f.hub,self.f.revision,self.f.root/'different')
    def test_new_project_intent_binds_real_image_and_keeps_runtime_references(self):
        from tests.test_local_project_guided import GuidedProjectTests
        from uas.native_qualification import validate_runtime_pair,native_review_configuration
        intent=GuidedProjectTests().intent();value=setup.guided_proposal(self.inspection,intent=intent)
        output=self.f.root/'new-project-plan'
        with patch.object(guided,'observe_quotas',return_value={'blocks':{},'inodes':{}}),patch.object(setup,'inspect',return_value=self.observed),patch('uas.local_engine_observe.inspect_exclusive',return_value=engine_observation()):
            setup.bind_guided(value,self.f.ws,self.f.hub,self.f.revision,output)
        request=json.loads((output/'request.json').read_bytes());config=request['rooms']['config']
        seats=validate_runtime_pair(config,config['rooms'][0])
        self.assertEqual(native_review_configuration(config,seats,[456])['reviewers'][0]['github_user_id'],123)
        self.assertEqual(config['deployment']['manager'],None)
        self.assertEqual(config['deployment']['images'][0]['reference'],request['rooms']['workstation']['image_id'])
        self.assertEqual({p['auth']['credential_ref'] for p in config['deployment']['providers']},{'pi-login','claude-login'})
        from uas.local_prepare import assemble
        from uas.local_native import LocalNativeProfile
        from uas.local_runtime_plan import LocalRuntimePlan
        identities={}
        def identity(path):
            if path not in identities:identities[path]=[8,len(identities)+1]
            return identities[path]
        settings=request['rooms']['settings']
        document=assemble(config,settings,request['rooms']['workstation'],request['rooms']['hub'],observe=identity)
        native=LocalNativeProfile(config,document,'demo',config['deployment']['state_root'])
        selection={'version':1,'profile':'local-runtime-v1','room_id':'demo','installation_id':native.nonce,
            'human_mergers':[456],**{k+'_manifest':{'path':'/private/'+k+'.json','sha256':'b'*64}
                                   for k in ('pi','claude','broker')}}
        text=(output.with_name(output.name+'-inputs')/'project.json').read_text()
        plan=LocalRuntimePlan(text,selection,installation_digest='c'*64,native_profile=native)
        self.assertEqual(plan.review_configuration()['reviewers'][0]['github_user_id'],123)
        self.assertEqual(plan.native_profile.host_profile.offset,1048576)
    def test_new_project_cli_no_manual_security_fields_or_project_json(self):
        output=self.f.root/'wizard'
        choices=['demo','org/project','builder','reviewer','123','122','pi-login','claude-login',
                 'Build Agent','builder@example.com','Review Agent','reviewer@example.com','']
        with patch.object(guided,'inspect_host',return_value=self.inspection),patch('builtins.input',side_effect=choices),patch.object(setup,'verified_output') as images,redirect_stdout(StringIO()):
            setup.main(['propose','--new-project','--output',str(output)])
        images.assert_not_called();value=json.loads((output/'proposal.json').read_bytes())
        self.assertEqual(value['intent']['profile'],'native-review-pair');self.assertIsNone(value['project'])
