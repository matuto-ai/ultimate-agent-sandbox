"""Canonical Engine ownership proof + complete foreign collision inventory."""
from contextlib import nullcontext
from types import SimpleNamespace as N
import json
import stat
import unittest
from unittest.mock import patch
from uas import local_room_prepare as prep,local_native as native
from uas.native_qualification_backend import names
from uas.lifecycle import Supervisor
from uas.docker_fixture import OwnershipConflict
from tests.test_local_native_v3 import selected

class ReadmissionInventoryTests(unittest.TestCase):
    def test_only_exact_canonical_resources_can_be_excluded(self):
        config,doc=selected();profile=native.LocalNativeProfile(config,doc,'room','/srv/uas/control')
        backend=native.LocalNativeBackend(profile);state={'room_id':'room','instance_id':'1'*32,'spec':profile.spec().document()}
        bad=[False]
        def command(owner,args,**kwargs):
            if args[:2]==['network','ls']:return names(state)[0]
            if args[:2]==['network','inspect']:
                return json.dumps([{'Id':'3'*64,'Name':names(state)[0],'Labels':backend._labels(state,'network'),'IPAM':{'Config':[{'Subnet':profile.subnet,'Gateway':profile.gateway}]}}])
            kind=args[2];name=args[3]
            if kind=='volume':
                labels=backend._labels(state,'volume')
                if bad[0]:labels[backend.LABEL+'.instance']='foreign'
                return json.dumps([{'Name':name,'Labels':labels}])
            hub=name.endswith('-hub');role='hub' if hub else 'container'
            return json.dumps([{'Id':('2' if hub else '1')*64,'Name':name,'Config':{'Labels':backend._labels(state,role)},'State':{'Running':False}}])
        node=N(st_uid=0,st_mode=stat.S_IFREG|0o600,st_nlink=1)
        with patch.object(prep.os.path,'lexists',return_value=True),patch.object(prep,'canonical_node',return_value=N(st_uid=0,st_mode=stat.S_IFDIR|0o700)),patch.object(prep.Path,'lstat',return_value=node),patch.object(Supervisor,'_locked',return_value=nullcontext()),patch.object(Supervisor,'_read',return_value=state),patch.object(native.LocalNativeBackend,'_run',command):
            owned=prep.readmission_owned_ids({'config':config},doc)
            self.assertEqual(owned,{'container':{'1'*64,'2'*64},'network':{'3'*64}})
            bad[0]=True
            with self.assertRaises(OwnershipConflict):prep.readmission_owned_ids({'config':config},doc)

    def test_owned_ids_do_not_hide_foreign_same_mcs_or_subnet(self):
        config,doc=selected();level=doc['rooms']['room']['mcs_level'];subnet=doc['rooms']['room']['subnet']
        owned={'container':{'1'*64},'network':{'3'*64}}
        foreign=[False]
        def read(args,**kwargs):
            if 'ps' in args:return '\n'.join(['1'*64]+(['4'*64] if foreign[0] else []))
            if args[3:5]==['network','ls']:return '\n'.join(['3'*64]+(['5'*64] if foreign[0] else []))
            resource=args[3];ids=args[7:]
            return '\n'.join(json.dumps({'id':i,'value':['system_u:system_r:container_t:'+level,'system_u:object_r:container_file_t:'+level] if resource=='container' else [{'Subnet':subnet}]}) for i in ids)
        with patch.object(prep,'run_fixed',side_effect=read):
            self.assertEqual(prep.observed_engine_allocations(doc['host_profile'],owned_ids=owned),{'levels':set(),'networks':set()})
            foreign[0]=True
            result=prep.observed_engine_allocations(doc['host_profile'],owned_ids=owned)
            self.assertEqual(result,{'levels':{level},'networks':{subnet}})
