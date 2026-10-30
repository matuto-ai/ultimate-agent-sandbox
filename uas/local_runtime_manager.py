"""Authenticated Manager on the persistent non-root native session owner thread.

Inputs come from the held root-supervised child startup, never from browser data.
No installation-file copy or credential provisioning. Each action remains within
one authenticated command. Admitted native work is stepped by the retained
owner after the opening HTTP request has ended, under its revocation lease.
"""
from contextlib import ExitStack
import hashlib
from pathlib import Path
import socket

from .ledger import RoomLedger
from .local_installation import canonical
from .local_manager import ManagerSelection
from .local_manager_actions import LocalNativeRunActions
from .local_manager_host import LocalProjection, require, instance
from .manager_stream import ManagerReadModel, RoomIdentity
from .manager_ui import ProjectBinding
from .local_runtime_plan import LocalRuntimePlan


def serve_runtime_manager(plan, resources, session_owner, manager_reference, *, stopped, on_ready=None):
    from .local_native_run_session import LocalNativeRunSession
    require(type(plan) is LocalRuntimePlan and type(session_owner) is LocalNativeRunSession
            and type(resources) is dict and callable(stopped)
            and (on_ready is None or callable(on_ready)), 'LOCAL_RUNTIME_MANAGER_OWNER_REQUIRED')
    session_owner._require_owner()
    require(session_owner.plan is plan and resources == session_owner.resources,
            'LOCAL_RUNTIME_MANAGER_SCOPE')
    session_owner.current()
    plan.require_unchanged()
    supervisor = session_owner.supervisor
    room = plan.room
    identity = RoomIdentity(plan.config['deployment']['id'],room['id'],resources['instance'])
    require(instance(supervisor)==identity.stream_id, 'LOCAL_MANAGER_INSTANCE_CHANGED')
    selection = ManagerSelection.read(manager_reference, deployment_id=identity.deployment_id,
        room_id=identity.room_id,instance_id=identity.stream_id,
        configuration_sha256=hashlib.sha256(canonical(plan.config)).hexdigest())
    context = selection.tls_context()
    actions = LocalNativeRunActions(session_owner)
    hostname, port = selection.authority.rsplit(':',1)
    family = socket.AF_INET6 if hostname=='[::1]' else socket.AF_INET
    address = '::1' if family==socket.AF_INET6 else '127.0.0.1'
    with ExitStack() as stack:
        listener = socket.socket(family,socket.SOCK_STREAM);stack.callback(listener.close)
        listener.bind((address,int(port)));listener.listen(8)
        ledger = RoomLedger.open_reader(resources['hub_ledger_path'],room['id']);stack.callback(ledger.close)
        model = ManagerReadModel(Path(resources['supervisor_directory'])/'runtime-manager.sqlite')
        stack.callback(model.close)
        projection = LocalProjection(ledger,model,supervisor,identity,
            ProjectBinding(identity,room['project']['id'],room['project']['repository']))
        stack.callback(projection.close)
        def current():
            session_owner.current()
            plan.require_unchanged()
            selection.require_unchanged(manager_reference)
        def document_for(session):
            return projection.refresh(session)
        manager = selection.manager(document_for,run_actions=actions,current=current)
        if on_ready is not None:
            on_ready({'status':'ready','url':'https://'+selection.authority+'/',
                'mode':'persistent-native-run','room_id':room['id'],'instance_id':identity.stream_id})
        manager.serve(listener,context,stopped,idle=session_owner.step)
