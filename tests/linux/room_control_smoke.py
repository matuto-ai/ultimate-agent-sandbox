#!/usr/bin/env python3
"""Hosted-only actual three-process control-plane lifetime/revocation proof.

The Workstation backend is explicitly a file-backed simulator. Hub/domain ledger,
Forge/Git service protocols, separate numeric UIDs, held kernel task identities,
Unix endpoints and human mTLS remote Start are real. No accounts, credentials,
Docker, VM, external network or production launch claim.
"""
import hashlib
from contextlib import ExitStack
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT),str(ROOT/'tests')]


def require(value, reason):
    if not value: raise AssertionError(reason)


def child(listener, name, private, instance):
    from uas.forge import ForgeBinding
    from uas.forge_audit import ForgeAudit
    channel, _ = listener.accept(); listener.close()
    with channel:
        if name == 'hub':
            from uas.ledger import RoomLedger
            from uas.peer import FixtureParticipant, FixturePeerHub
            from uas.room_hub import serve
            ledger = RoomLedger(private/'room.db','alpha')
            try:
                hub = FixturePeerHub(ledger)
                hub.configure('initial', (FixtureParticipant('alice','actor-a'),FixtureParticipant('bob','actor-b')), 'run-one')
                def grow_history(state, command):
                    state['retained-test-history']='x'*70000
                    return hub._transition(state,'fixture.history',{}, {'retained':True})
                hub._control('retained-history','history',{},grow_history)
                serve(channel,hub,instance,supervisor_uid=0,supervisor_gid=0)
            finally: ledger.close()
        else:
            binding = ForgeBinding('alpha','project','owner/repo')
            audit = ForgeAudit(private/'audit.db','deployment')
            try:
                if name == 'forge':
                    from uas.forge_read import ExternalReadBroker
                    from uas.forge_read_service import serve
                    def no_provider(actor):
                        raise AssertionError('this lifecycle test must not contact providers')
                    broker = ExternalReadBroker(binding,instance,audit,no_provider,private/'results')
                    serve(channel,broker,supervisor_uid=0,supervisor_gid=0)
                else:
                    from uas.git_audit import GitAudit
                    from uas.git_service import ExternalGitBroker, serve
                    from uas.git_transport import GitTransportConfig, SshTransport
                    executable = Path('/usr/bin/ssh').resolve(strict=True)
                    config = GitTransportConfig(str(executable),hashlib.sha256(executable.read_bytes()).hexdigest(),())
                    transport = SshTransport(config,binding)
                    try:
                        broker = ExternalGitBroker(binding,instance,GitAudit(audit),transport)
                        serve(channel,broker,supervisor_uid=0,supervisor_gid=0)
                    finally: transport.close()
            finally: audit.close()


def run():
    if (os.getuid()!=0 or os.environ.get('GITHUB_ACTIONS')!='true'
            or os.environ.get('RUNNER_OS')!='Linux' or os.environ.get('UAS_ROOM_CONTROL_TEST')!='1'):
        raise SystemExit('explicit reviewed hosted Linux root gate required')
    from lifecycle_support import FileFixtureBackend
    from uas.lifecycle import FixtureSpec, Supervisor
    from uas.forge import ForgeBinding
    from uas.forge_read_service import ReadBrokerClient
    from uas.git_service import GitBrokerClient
    from uas.kernel_origin import alive, enable, probe
    from uas.room_control_plane import RoomControlPlane
    from uas.room_hub import RoomHubClient
    from uas.room_remote_start import RemoteStart, StartCertificateBindings, PATH
    from uas.workstation_exec import EndpointLease
    from uas.manager_transport import client_tls_context, server_tls_context, send_frame, receive_frame
    probe()
    children=[]; clients=[]; exit_proofs={}; owned=ExitStack(); manager_proof=None
    with tempfile.TemporaryDirectory(prefix='uas-room-') as temporary:
        root=Path(temporary); root.chmod(0o755)
        project=root/'project'; project.mkdir(); (project/'retain').write_text('human data')
        class CheckedBackend(FileFixtureBackend):
            def remove(self,state,kind):
                require(set(exit_proofs)=={'hub','forge','git'} and all(not alive(fd) for fd in exit_proofs.values()),'live service before Workstation removal')
                require(manager_proof is not None and manager_proof.worker.status()['terminated'],'Manager exporter alive before resource removal')
                require(all(not os.path.lexists(path) for path in endpoints),'endpoint exists before Workstation removal')
                super().remove(state,kind)
        backend=CheckedBackend(root/'resources')
        supervisor=Supervisor(root/'control','alpha',backend,authorize=lambda *_:True,revoke=backend.revoke)
        spec=FixtureSpec('alpha','project',(str(project),),'sha256:'+'a'*64,'sha256:'+'b'*64,'sha256:'+'c'*64)
        started=supervisor.start(spec); instance=started['instance_id']
        owner=RoomControlPlane(supervisor); instance_dir=owner.directory
        for path in (root/'control',supervisor.directory,instance_dir.parent,instance_dir,instance_dir/'data'):
            path.chmod(0o711)  # Traverse only; manifests remain root-private.
        endpoints=[]
        try:
            for name, uid in (('hub',65530),('forge',65531),('git',65532)):
                private=instance_dir/'data'/name; private.mkdir(mode=0o700); os.chown(private,uid,uid)
                directory=instance_dir/'data'/(name+'-endpoint'); directory.mkdir(mode=0o710); os.chown(directory,0,uid)
                endpoint=directory/'service.sock'
                listener=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET)
                enable(listener); listener.bind(str(endpoint)); os.chown(endpoint,0,uid); endpoint.chmod(0o620); listener.listen(1)
                lease=EndpointLease(endpoint,owner=0,group=uid); endpoints.append(endpoint)
                pid=os.fork()
                if pid==0:
                    try:
                        # Do not retain another service's authenticated channels.
                        for client in clients: client.channel.close()
                        os.setgroups([]); os.setgid(uid); os.setuid(uid)
                        child(listener,name,private,instance)
                    except BaseException:
                        import traceback; traceback.print_exc()
                        os._exit(1)
                    os._exit(0)
                children.append(pid); listener.close()
                channel=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET); enable(channel); channel.settimeout(5); channel.connect(str(endpoint))
                if name=='hub':
                    client=RoomHubClient(channel,'alpha',instance,hub_uid=uid,hub_gid=uid)
                    owner.attach_hub(client,endpoints=(lease,)); hub=client
                elif name=='forge':
                    client=ReadBrokerClient(channel,supervisor,ForgeBinding('alpha','project','owner/repo'),instance,worker_uid=uid,worker_gid=uid)
                    owner.attach_forge(client,endpoints=(lease,))
                else:
                    client=GitBrokerClient(channel,ForgeBinding('alpha','project','owner/repo'),instance,broker_uid=uid,broker_gid=uid)
                    owner.attach_git(client,endpoints=(lease,))
                clients.append(client)
                exit_proofs[name]=os.dup(client.worker.pidfd)
            initial=hub.status(); identities={name:lease.origin.identity for name,lease in owner.services.items()}
            require(initial['room_seq']>0 and initial['configured'] and initial['state_bytes']>65536,'actual Hub configured state missing')
            from test_manager_tls import HostedManagerTLSTests
            from manager_worker_fixture import hosted_manager_worker
            from uas.manager_stream import RoomIdentity
            HostedManagerTLSTests.setUpClass(); owned.callback(HostedManagerTLSTests.doClassCleanups)
            certs=HostedManagerTLSTests.certroot
            config=json.loads((ROOT/'tests/fixtures/two-rooms.json').read_text())
            config['deployment']['state_root']=str(root/'manager-config')
            for room in config['rooms']:
                room['state_root']=str(root/'manager-config'/room['id'])
                for role in room['project']['roots']:
                    path=root/'config-projects'/room['id']/role; path.mkdir(parents=True)
                    room['project']['roots'][role]=str(path)
            identity=RoomIdentity(config['deployment']['id'],'alpha',owner.document['stream_id'])
            manager_proof=owned.enter_context(hosted_manager_worker(supervisor,instance_dir/'data/hub/room.db',identity,config,certs))
            owner.attach_manager_worker(manager_proof.worker)
            received=lambda phase:lambda p:p['sections']['room_lifecycle']['value']['alpha']['phase']==phase
            manager_proof.wait_projection(received('running'))
            require(supervisor.stop()['phase']=='stopped','simulated Workstation stop failed')
            manager_proof.wait_projection(received('stopped'))
            require(not manager_proof.worker.status()['terminated'],'Workstation Stop terminated exporter')
            time.sleep(46)  # Exceeds both former 35s/45s Broker idle lifetimes.
            require(hub.status()['state_digest']==initial['state_digest'],'Hub state lost while Workstation stopped')
            require(all(alive(lease.origin.pidfd) for lease in owner.services.values()),'control plane died on Stop')
            # Use generated test-only certificates and the real TLS framing path.
            from test_manager_tls import HostedManagerTLSTests
            try:
                certs=HostedManagerTLSTests.certroot
                der=ssl.PEM_cert_to_DER_cert((certs/'alpha.crt').read_text())
                wrong=ssl.PEM_cert_to_DER_cert((certs/'beta.crt').read_text())
                bindings=StartCertificateBindings({hashlib.sha256(der).hexdigest():('human','alpha',instance),
                    hashlib.sha256(wrong).hexdigest():('other-human','alpha','other-instance')})
                remote=RemoteStart(supervisor,bindings)
                server_context=server_tls_context(trust_file=str(certs/'ca.crt'),certificate_file=str(certs/'manager.crt'),private_key_file=str(certs/'manager.key'))
                client_context=client_tls_context(trust_file=str(certs/'ca.crt'),certificate_file=str(certs/'alpha.crt'),private_key_file=str(certs/'alpha.key'))
                listener=socket.socket(); listener.bind(('127.0.0.1',0)); listener.listen(2); listener.settimeout(5)
                port=listener.getsockname()[1]; errors=[]
                def serve_start():
                    for _ in range(4):
                        try:
                            raw,_=listener.accept(); raw.settimeout(5)
                            with server_context.wrap_socket(raw,server_side=True) as secure: remote.serve_once(secure)
                        except BaseException as error: errors.append(getattr(error,'code',type(error).__name__))
                thread=threading.Thread(target=serve_start); thread.start()
                request={'version':1,'kind':'start','operation_id':'remote-one','observed_revision':supervisor._read()['observation_revision']}
                replies=[]
                for name in ('beta','unregistered'):
                    context=client_tls_context(trust_file=str(certs/'ca.crt'),certificate_file=str(certs/(name+'.crt')),private_key_file=str(certs/(name+'.key')))
                    try:
                        with socket.socket() as raw:
                            raw.settimeout(5); raw.connect(('127.0.0.1',port))
                            with context.wrap_socket(raw,server_hostname='localhost') as secure:
                                send_frame(secure,request,path=PATH,host='localhost')
                                receive_frame(secure,response=True,path=PATH)
                    except Exception:
                        pass
                    else: raise AssertionError('unauthorized TLS identity accepted')
                    require(supervisor._read()['phase']=='stopped','unauthorized Start mutated lifecycle')
                for _ in range(2):
                    with socket.socket() as raw:
                        raw.settimeout(5); raw.connect(('127.0.0.1',port))
                        with client_context.wrap_socket(raw,server_hostname='localhost') as secure:
                            send_frame(secure,request,path=PATH,host='localhost')
                            replies.append(receive_frame(secure,response=True,path=PATH))
                thread.join(6); listener.close()
                require(not thread.is_alive() and errors==['START_INSTANCE_MISMATCH','START_HUMAN_CERTIFICATE_UNREGISTERED'],'authenticated Start service/negative proof failed')
                require(replies[0]==replies[1] and replies[0]['phase']=='running','Start receipt replay differs')
            finally: pass  # Shared fixture certificates remain until owned cleanup.
            manager_proof.wait_projection(received('running'))
            require(identities=={name:lease.origin.identity for name,lease in owner.services.items()},'Start replaced persistent services')
            require(hub.status()['state_digest']==initial['state_digest'],'Start replaced persistent Hub ledger')
            # A live client operation lock must defer killing that Broker and
            # all Workstation cleanup, without blocking under lifecycle lock.
            git_client = clients[-1]
            git_client._stream_lock.acquire()
            try:
                busy = supervisor.destroy()
                require(busy['phase']=='destroy_failed' and alive(git_client.worker.pidfd),'busy Git Broker was killed')
                require(any(x['name']==instance+':git' and x['reason']=='SERVICE_OPERATION_ACTIVE' for x in busy['leftovers']),'busy service not identified')
                require(backend.inspect(supervisor._read(),'container') is not None,'Workstation removed during active service operation')
            finally: git_client._stream_lock.release()
            git_client.close()  # Simulate accepted-operation cancellation cleanup.
            require(owner.services['git'].origin.pidfd>=0,'client close lost lifecycle kernel handle')
            retained = owner.services['git']
            supervisor = Supervisor(root/'control','alpha',backend,authorize=lambda *_:True,revoke=backend.revoke)
            owner = RoomControlPlane(supervisor)
            owner.recover(retained,client=git_client)
            require(manager_proof.worker.join(3),'Manager worker did not finish after Destroy request')
            owner.recover_manager_worker(manager_proof.worker)
            retained.origin.close()  # New owner must hold its own exact descriptor.
            require(owner.services['git'].origin.pidfd>=0,'recovered owner lost independent process handle')
            # Replace one endpoint with unrelated data. Destroy must stop all
            # service processes, preserve the foreign path and refuse resources.
            original = endpoints[-1].with_name('retained-original.sock')
            endpoints[-1].rename(original)
            endpoints[-1].write_text('unowned replacement')
            backend.calls.clear()
            refused = supervisor.destroy()
            require(refused['phase']=='destroy_failed','replaced endpoint accepted')
            require(endpoints[-1].read_text()=='unowned replacement','unowned endpoint removed')
            require(not any(c.startswith('remove') for c in backend.calls),'resources removed before verified revocation')
            require(any(x['name']==str(endpoints[-1]) for x in refused['leftovers']),'exact Git leftover missing')
            endpoints[-1].unlink(); original.rename(endpoints[-1])  # Explicit test-operator repair only.
            # Fail deletion after all real processes/endpoints were revoked.
            backend.fail_before.add('remove-volume')
            failed=supervisor.destroy()
            require(failed['phase']=='destroy_failed','partial Destroy did not remain failed')
            require(set(exit_proofs)=={'hub','forge','git'} and all(not alive(fd) for fd in exit_proofs.values()),'service survived Destroy')
            require(all(not os.path.lexists(path) for path in endpoints),'owned endpoint survived Destroy')
            require((project/'retain').read_text()=='human data','Project data changed')
            # Reconstruct without process handles; durable verified-exit proof
            # must allow targeted cleanup rather than inventing a new PID owner.
            reopened=Supervisor(root/'control','alpha',backend,authorize=lambda *_:True,revoke=backend.revoke)
            restored=RoomControlPlane(reopened)
            backend.fail_before.clear()
            from unittest.mock import patch
            from uas.lifecycle import LifecycleError
            with patch.object(reopened,'_tombstone',side_effect=LifecycleError('TOMBSTONE_TEST_FAILURE')):
                require(reopened.reconcile()['phase']=='destroy_failed','tombstone failure not retained')
            require(not restored.directory.exists(),'owned data not removed before tombstone failure')
            final_owner=Supervisor(root/'control','alpha',backend,authorize=lambda *_:True,revoke=backend.revoke)
            require(final_owner.reconcile()['phase']=='destroyed','fresh-owner tombstone retry after directory removal failed')
            require((project/'retain').exists(),'Project removed')
            recreated=reopened.start(spec)
            require(recreated['instance_id']!=instance,'recreation reused old Room instance')
            print(json.dumps({'real_services':sorted(identities),'workstation':'file-backed simulator','remote_start':'actual mutual TLS + replay','stop':'persistent processes and Hub state retained','destroy':'all real service exits + actual endpoints removed + targeted recovery','provider_contact':False}),flush=True)
        finally:
            owned.close()
            for pid in children:
                try:
                    waited,_=os.waitpid(pid,os.WNOHANG)
                    if not waited:
                        os.kill(pid,signal.SIGKILL); os.waitpid(pid,0)
                except ChildProcessError: pass
            for client in clients:
                client.close()
            for descriptor in exit_proofs.values():
                os.close(descriptor)


if __name__=='__main__': run()
