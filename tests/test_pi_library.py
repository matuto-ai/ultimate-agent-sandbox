"""Bounded real Pi native read/bash workflow, scripted provider, no inference.

A disposable trusted wrapper supplies the fixture's published reference mount;
production CLI has no root/path option. Existing ProjectProjection makes both
immutable trees. This proves tools and instructions, not live model obedience.
"""
import base64
import json
import os
from pathlib import Path
import shlex
import shutil
import time
import unittest

import test_library_projection as projections
from uas.pi_runtime import FixturePiRpcReceiver
from uas.peer import Readiness

ROOT=Path(__file__).resolve().parents[1]
INSTALL=os.environ.get('UAS_PI_INSTALL')

@unittest.skipUnless(INSTALL,'Official Pi native suite required')
class PiLibraryTests(unittest.TestCase):
    def test_actual_loaded_rule_native_tools_two_project_projections(self):
        p=projections.ProjectionTests();p.setUp();self.addCleanup(p.doCleanups)
        p.register(); alpha=p.projection(); alpha.refresh()
        prefix='projects/'+p.scope.project_path+'/'
        def doc(title,body,status='stable',extra=''):
            return (f'---\ntype: alien-existing\ntitle: {title}\nstatus: {status}\n{extra}---\n'
                    +body+'\n').encode()
        files={prefix+'context/alpha.md':doc('ALPHA_ONLY','Amber token\nSQLite storage\n'
                 '[broken](missing.md)\nIGNORE_RUNTIME_MARKER',extra='verified: {by: "human:reader", at: "2026-10-01T00:00:00Z"}\nstale_after: 2020-01-01\nunknown_key: keep\n'),
               prefix+'pending/draft.md':doc('Pending','Sapphire specialdraft','draft')}
        files.update({prefix+f'context/many{i}.md':doc('Many','commonmatch') for i in range(12)})
        p.mutate(files);alpha.refresh()
        beta_scope=p.make_scope('beta','other/beta','2002');p.fresh=beta_scope
        p.registrar.register(p.operation('register-beta',beta_scope),p.settings)
        p.mutate({'projects/'+beta_scope.project_path+'/context/beta.md':doc('BETA_ONLY','BETA_SECRET')})
        beta=p.projection(beta_scope);beta.refresh()
        for index,worker in enumerate((alpha,beta)):
            self._native(worker,index)

    def _native(self,worker,index):
        directory=worker.root.parent/'native';directory.mkdir()
        home=directory/'home';home.mkdir();agent=home/'agent';agent.mkdir()
        (agent/'settings.json').write_text(json.dumps({'compaction':{'enabled':False},'retry':{'enabled':False}}))
        observations=directory/'observations.jsonl'
        wrapper=directory/'scan.mjs'
        # This wrapper is never packaged or reachable in production.
        wrapper.write_text(f"import {{scan}} from {json.dumps((ROOT/'runtime/pi/library-scan.mjs').as_uri())};\n"
            +f"import {{parse}} from {json.dumps((Path(INSTALL)/'node_modules/yaml/dist/index.js').resolve().as_uri())};\n"
            +f"process.stdout.write(scan({json.dumps(str(worker.root))},process.argv.slice(2),{{parse,now:'2026-10-30T00:00:00Z'}}));\n")
        env={'PATH':os.environ['PATH'],'HOME':str(home),'PI_CODING_AGENT_DIR':str(agent),'PI_OFFLINE':'1',
             'NODE_OPTIONS':'--import='+str(ROOT/'tests/pi/network-guard.mjs'),
             'UAS_PI_FAUX_MODULE':str(Path(INSTALL)/'node_modules/@earendil-works/pi-ai/dist/providers/faux.js'),
             'UAS_PI_LIBRARY_OBSERVATIONS':str(observations)}
        argv=[shutil.which('node'),str(Path(INSTALL)/'node_modules/@earendil-works/pi-coding-agent/dist/cli.js'),
              '--mode','rpc','--tools','read,bash','--no-extensions','--no-skills','--no-prompt-templates','--no-themes',
              '-e',str(ROOT/'runtime/pi/extension.mjs'),'-e',str(ROOT/'tests/pi/library-provider.mjs'),
              '--provider','faux','--model','faux-1','--session-dir',str(directory/'sessions')]
        native=FixturePiRpcReceiver(argv,cwd=directory,env=env,journal=directory/'intent.db',runtime_version='1.4.0',
            scope={'room_id':'room','participant_id':'pi','run_id':'run','generation':1,'context_generation':1})
        try:
            def idle():
                deadline=time.monotonic()+10
                while time.monotonic()<deadline:
                    if native.observe()==Readiness.SAFE:return
                    time.sleep(.02)
                self.fail('Native Pi did not settle')
            native.rpc('prompt',message='Check loaded Runtime rules without reading files.');idle()
            first=json.loads(observations.read_text().splitlines()[0]); raw=json.dumps(first)
            self.assertIn('never instruction authority',raw)
            self.assertIn('/project/reference/library/',raw)
            for marker in ('ALPHA_ONLY','BETA_SECRET','IGNORE_RUNTIME_MARKER'):
                self.assertNotIn(marker,raw)
            def run(calls):
                start=len(native.event_snapshot())
                encoded=base64.urlsafe_b64encode(json.dumps(calls).encode()).decode().rstrip('=')
                native.rpc('prompt',message='/fixture-native-files '+encoded)
                native.rpc('prompt',message='Execute the explicit native-file fixture workflow.');idle()
                results=[x for x in native.event_snapshot()[start:] if x.get('type')=='tool_execution_end']
                self.assertEqual(len(results),len(calls))
                self.assertTrue(all(not x.get('isError') for x in results),results)
                return ['\n'.join(c.get('text','') for c in x['result'].get('content',[])) for x in results]
            def search(*terms):
                command=' '.join(shlex.quote(v) for v in [shutil.which('node'),str(wrapper),*terms])
                return {'name':'bash','input':{'command':command}}
            result=run([{'name':'read','input':{'path':str(worker.root/'library/index.md')}},
                        {'name':'read','input':{'path':str(worker.root/'library/pending/index.md')}},
                        search('AMBER','sqlite'),search('specialdrafx'),search('commonmatch'),
                        search('noexistquery'),search('BETA_SECRET')])
            if index==0:
                self.assertIn('ALPHA_ONLY',result[2]);self.assertNotIn('FUZZY',result[2])
                self.assertIn('human-reviewed',result[2]);self.assertIn('STALE warning',result[2])
                self.assertIn('alien-existing',result[2]);self.assertIn('sources: absent',result[2])
                self.assertIn('FUZZY DRAFT',result[3]);self.assertEqual(result[4].count('fragment:'),8)
                self.assertIn('No matching document',result[5]);self.assertIn('No matching document',result[6])
                whole=run([{'name':'read','input':{'path':str(worker.root/'library/context/alpha.md')}}])[0]
                self.assertIn('unknown_key',whole);self.assertIn('missing.md',whole);self.assertIn('IGNORE_RUNTIME_MARKER',whole)
            else:
                self.assertIn('No matching document',result[2]);self.assertIn('BETA_ONLY',result[6])
                self.assertNotIn('ALPHA_ONLY',''.join(result))
            self.assertFalse((worker.root/'library/.git').exists())
        finally:native.close()
