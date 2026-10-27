"""Pure control-flow verification of hosted scenario; no native entrypoint import."""
import ast
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from uas.forge import ForgeBinding
from uas.forge_audit import ForgeAudit
from uas.forge_mutations import ExternalMutationBroker
from uas.forge_read_provider import BrokerReadProvider
from uas.forge_read_service import ReadBrokerClient
from uas.github_read import GitHubProject
from uas.github_mutations import GitHubMutationProvider
import json
from uas.review_broker import ExternalReviewBroker
from test_github_surface import pull, response
from review_hosted_scenario import exercise

ROOT=Path(__file__).resolve().parents[1]


class ReviewHostedTests(unittest.TestCase):
    def test_exact_scenario_with_actual_reducers_and_controlled_transport(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);phase='prepare';comments=[];posts=[]
            project=GitHubProject('owner/repo');binding=ForgeBinding('alpha','project','owner/repo')
            def get(path):
                clean=path.partition('?')[0];base='repos/owner/repo';api='https://api.github.com/'+base
                if clean==base+'/pulls/11':
                    if phase=='outage':return response({},503)
                    value=pull(11,'owner/repo');value['id']=111
                    value['head']['sha']='a'*40;value['base']['sha']='b'*40;value['merge_commit_sha']=None
                    if phase=='merged':
                        value.update(merged=True,state='closed',merge_commit_sha='c'*40,merged_by={'id':7,'type':'User'})
                        value['base']['sha']='c'*40
                    return response(value)
                if clean==base+'/pulls/11/reviews':
                    identifier=3 if phase in {'repass','merged'} else 2 if phase in {'pass','comment'} else 1
                    return response([] if phase=='prepare' else [{'id':identifier,
                        'html_url':f'https://github.com/owner/repo/pull/11#pullrequestreview-{identifier}',
                        'pull_request_url':api+'/pulls/11','user':{'id':8,'login':'fixture-reviewer'},
                        'state':'APPROVED' if identifier>=2 else 'CHANGES_REQUESTED','submitted_at':'2026-10-27T21:00:00Z',
                        'commit_id':'d'*40 if phase=='stale' else 'a'*40}])
                if clean==base+'/commits/'+'c'*40:
                    return response({'sha':'c'*40,'url':api+'/commits/'+'c'*40,'parents':[{'sha':'b'*40},{'sha':'a'*40}]})
                raise AssertionError(path)
            def mutate(method,path,body):
                api='https://api.github.com/repos/owner/repo'
                if method=='GET':
                    if path=='user': return response({'id':41,'login':'fixture-actor'})
                    if path=='repos/owner/repo': return response({'id':900,'full_name':'owner/repo','html_url':'https://github.com/owner/repo'})
                    if path.startswith('repos/owner/repo/issues/11/comments?'): return response(comments)
                    if path=='repos/owner/repo/issues/11':
                        value=json.loads(get('repos/owner/repo/pulls/11').body)
                        return response({**value,'id':100111,'repository_url':api,'pull_request':{'url':api+'/pulls/11'}})
                    return get(path)
                self.assertEqual('POST',method);self.assertEqual('repos/owner/repo/issues/11/comments',path)
                posts.append(body)
                comments.append({'id':701,'user':{'id':41,'login':'fixture-actor'},'body':body['body'],
                    'url':api+'/issues/comments/701','issue_url':api+'/issues/11'})
                raise OSError('lost synthetic reply')
            provider=BrokerReadProvider(project,get,None)
            with ForgeAudit(root/'audit.db','deployment') as audit:
                mutations=ExternalMutationBroker(binding,'instance-1',audit,{'actor-a':41},lambda _:GitHubMutationProvider(project,mutate))
                external=ExternalReviewBroker(binding,'instance-1',audit,'actor-a',lambda _:provider,mutations)
                client=object.__new__(ReadBrokerClient);client.review_enabled=True
                client.binding=binding;client.room_instance='instance-1'
                client.supervisor=SimpleNamespace(_locked=lambda:nullcontext(),_read=lambda:{'phase':'running','instance_id':'instance-1'})
                client.prepare=lambda envelope,origin,authorize:(envelope,origin,authorize)
                client.perform=lambda packet:external.execute(packet[0],origin=packet[1],authorize=packet[2])
                for phase in ('prepare','stale','outage','changes','pass','comment','repass','merged'):
                    with self.subTest(phase=phase):
                        result=exercise(client,root/'room.db',phase)
                        self.assertEqual('CLOSED' if phase=='merged' else 'ACTIVE',result['run_status'])
                self.assertEqual(1,len(posts))
    def test_hosted_entrypoint_is_explicit_bounded_and_stages_private_code(self):
        source=(ROOT/'tests/linux/review_forge_smoke.py').read_text()
        ast.parse(source)
        self.assertIn("os.environ.get('GITHUB_ACTIONS')!='true'",source)
        self.assertIn("os.environ.get('RUNNER_OS')!='Linux'",source)
        self.assertIn('worker_uid=65531,worker_gid=65531',source)
        self.assertNotIn("copytree",source)
        self.assertIn("for name in SOURCES:",source)
        self.assertIn('secret not in out and secret not in err',source)
        workflow=(ROOT/'.github/workflows/validate.yml').read_text()
        self.assertIn('30s sudo -n --preserve-env=GITHUB_ACTIONS,RUNNER_OS /usr/bin/python3 tests/linux/review_forge_smoke.py & review=$!',workflow)
        self.assertIn('for child in "$diff" "$broker" "$review"',workflow)

    def test_fixed_staged_eager_import_closure_and_exercised_lazy_owner(self):
        tree=ast.parse((ROOT/'tests/linux/review_forge_smoke.py').read_text())
        sources=next(ast.literal_eval(node.value) for node in tree.body if isinstance(node,ast.Assign)
                     and any(isinstance(name,ast.Name) and name.id=='SOURCES' for name in node.targets))
        self.assertEqual(len(sources),len(set(sources)))
        self.assertLessEqual(len(sources),48)
        self.assertLessEqual(sum((ROOT/name).stat().st_size for name in sources),8*1024*1024)
        class Eager(ast.NodeVisitor):
            def __init__(self):self.dependencies=set()
            def visit_FunctionDef(self,node):pass
            def visit_AsyncFunctionDef(self,node):pass
            def visit_ImportFrom(self,node):
                if node.level==1 and node.module:self.dependencies.add('uas/'+node.module.replace('.','/')+'.py')
        for name in sources:
            scanner=Eager();scanner.visit(ast.parse((ROOT/name).read_text()))
            self.assertLessEqual(scanner.dependencies,set(sources),(name,scanner.dependencies-set(sources)))
        self.assertLessEqual({'uas/github_executor.py','uas/forge_read_provider.py','uas/github_logs.py',
            'uas/review_broker.py','uas/run_review.py','uas/workstation_peer.py','uas/gate_hub.py','uas/run_control.py'},set(sources))

    def test_embedded_fixture_and_supervisor_compile_without_running(self):
        gate=ast.parse((ROOT/'tests/linux/gate_forge_smoke.py').read_text())
        base=next(ast.literal_eval(node.value) for node in gate.body if isinstance(node,ast.Assign)
                  and any(isinstance(name,ast.Name) and name.id=='FAKE_GH' for name in node.targets))
        tree=ast.parse((ROOT/'tests/linux/review_forge_smoke.py').read_text())
        namespace={'GATE_FIXTURE':base}
        for node in tree.body:
            if isinstance(node,ast.Assign) and any(isinstance(name,ast.Name) and name.id in {'FAKE_GH','SUPERVISOR'} for name in node.targets):
                value=eval(compile(ast.Expression(node.value),'<fixture-string>','eval'),{'__builtins__':{}},namespace)
                namespace[node.targets[0].id]=value
        ast.parse(namespace['FAKE_GH'])
        ast.parse(namespace['SUPERVISOR'])
        self.assertIn("state['posts']+=1",namespace['FAKE_GH'])
        self.assertIn('os._exit(13)',namespace['FAKE_GH'])
