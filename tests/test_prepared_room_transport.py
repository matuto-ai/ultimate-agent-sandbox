import copy
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock
import urllib.error
import zipfile

sys.path.insert(0, str(Path(__file__).parent / 'vm'))
try:
    import fetch_prepared_room as transport
finally:
    sys.path.pop(0)


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.chosen = transport.selection('123','456','a'*40,'b'*64)
        self.run = {'id':123,'head_sha':'a'*40,'status':'completed','conclusion':'success',
            'event':'workflow_dispatch','path':transport.WORKFLOW,'repository':{'id':1,'full_name':transport.REPOSITORY},
            'head_repository':{'id':1},'actor':{'login':'puglab-reviewer'},'triggering_actor':{'login':'puglab-reviewer'}}
        self.artifact = {'id':456,'expired':False,'name':'room-prepared-123','size_in_bytes':10,
            'digest':'sha256:'+'c'*64,'workflow_run':{'id':123,'head_sha':'a'*40,'repository_id':1,'head_repository_id':1}}

    def test_workflow_transport_is_deliberate_scoped_and_explicit(self):
        workflows=Path(__file__).parents[1]/'.github/workflows'
        consumer=(workflows/'room-launch.yml').read_text()
        producer=(workflows/'room-prepare.yml').read_text()
        for source,label in ((consumer,'qualify-room-launch'),(producer,'prepare-room-base')):
            triggers=source.split('\non:\n',1)[1].split('\npermissions:',1)[0]
            self.assertEqual({'  pull_request:','  workflow_dispatch:'},
                             {line for line in triggers.splitlines() if line.startswith('  ') and not line.startswith('   ')})
            self.assertIn('    types: [labeled]',triggers)
            self.assertIn("github.event.label.name == '"+label+"'",source)
            self.assertIn("github.event.sender.login == 'puglab-reviewer'",source)
            self.assertIn("github.event_name == 'workflow_dispatch' && github.actor == 'puglab-reviewer'",source)
            self.assertIn('github.event.pull_request.head.repo.full_name == github.repository',source)
            self.assertIn('persist-credentials: false',source)
            self.assertIn('    timeout-minutes: 30',source)
            self.assertNotIn('secrets.',source)
            self.assertNotIn('continue-on-error',source)
        self.assertEqual(1,consumer.count('actions: read'))
        self.assertIn('    permissions:\n      contents: read\n      actions: read',consumer)
        self.assertNotIn('actions:',producer)
        for field in ('producer_run_id','artifact_id','producer_commit','receipt_sha256'):
            self.assertIn('      '+field+':',consumer)
        self.assertIn('--selection-file tests/vm/prepared-room-selection.json',consumer)
        self.assertIn('UAS_ROOM_EXECUTION: warm',consumer)
        self.assertIn('UAS_ROOM_PREPARED_SHA256=',consumer)
        self.assertIn('retention-days: 7',producer)
        self.assertIn('overwrite: false',producer)
        self.assertIn('UAS_ROOM_PRODUCER_COMMIT:',producer)
        self.assertIn('actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02',producer)

    def test_exact_metadata_and_pr_checkout_binding(self):
        self.assertEqual(transport.verify_metadata(self.run,self.artifact,self.chosen),'c'*64)
        self.run.update(event='pull_request',head_sha='d'*40,pull_requests=[{'head':{'sha':'a'*40,'repo':{'id':1}}}])
        self.artifact['workflow_run']['head_sha']='d'*40
        self.assertEqual(transport.verify_metadata(self.run,self.artifact,self.chosen),'c'*64)
        self.run['pull_requests'][0]['head']['repo']['id']=2
        with self.assertRaises(ValueError): transport.verify_metadata(self.run,self.artifact,self.chosen)

    def test_metadata_rejects_wrong_run_commit_workflow_actor_and_fork(self):
        for field,value in [('id',124),('head_sha','d'*40),('status','in_progress'),('conclusion','failure'),
                ('event','push'),('path','.github/workflows/other.yml'),('actor',{'login':'other'}),
                ('triggering_actor',{'login':'other'}),('head_repository',{'id':2}),
                ('repository',{'id':1,'full_name':'other/repo'})]:
            with self.subTest(field=field):
                run=copy.deepcopy(self.run);run[field]=value
                with self.assertRaises(ValueError): transport.verify_metadata(run,self.artifact,self.chosen)

    def test_metadata_rejects_expired_wrong_artifact_and_binding(self):
        for field,value in [('id',457),('expired',True),('name','latest'),('size_in_bytes',0),
                ('size_in_bytes',transport.MAX_ZIP+1),('digest',None),('workflow_run',{'id':999})]:
            with self.subTest(field=field,value=value):
                artifact=copy.deepcopy(self.artifact);artifact[field]=value
                with self.assertRaises(ValueError): transport.verify_metadata(self.run,artifact,self.chosen)

    def test_selection_is_explicit_not_latest(self):
        for values in [('latest','456','a'*40,'b'*64),('0','456','a'*40,'b'*64),('123','456','main','b'*64),
                       ('123','456','a'*40,'b'*63),(True,'456','a'*40,'b'*64)]:
            with self.assertRaises(ValueError): transport.selection(*values)

    def archive(self, root, extra=(), omit=()):
        path=root/'artifact.zip'
        with zipfile.ZipFile(path,'w') as archive:
            for name in ('base.qcow2','receipt.json','pool/fedora-44.asc','pool/rpms/package.rpm','pool/rpms/repodata/repomd.xml'):
                if name not in omit: archive.writestr(name,b'bytes')
            for name,data in extra: archive.writestr(name,data)
        return path

    def test_extract_fixed_inventory_without_native_effects(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(Path,'chmod') as chmod:
            root=Path(tmp); archive=self.archive(root); output=root/'new'
            transport.extract(archive,output)
            self.assertEqual((output/'base.qcow2').read_bytes(),b'bytes')
            self.assertEqual(chmod.call_count,5)
            for call in chmod.call_args_list:self.assertEqual(call.args,(0o600,))

    def test_extract_rejects_traversal_absolute_duplicate_and_unknown(self):
        for name in ('../escape','/escape','pool/../escape','pool//x','pool\\escape','unknown','receipt.json'):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);archive=self.archive(root,[(name,b'x')])
                with self.assertRaises(ValueError): transport.extract(archive,root/'new')
                self.assertFalse((root/'new').exists())

    def test_extract_rejects_symlink_and_size_and_missing(self):
        info=zipfile.ZipInfo('pool/rpms/link.rpm');info.create_system=3;info.external_attr=(stat.S_IFLNK|0o777)<<16
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); archive=self.archive(root,[(info,b'/etc/passwd')])
            with self.assertRaises(ValueError):transport.extract(archive,root/'new')
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);archive=self.archive(root,omit=('base.qcow2',))
            with self.assertRaises(ValueError):transport.extract(archive,root/'new')
        with tempfile.TemporaryDirectory() as tmp,mock.patch.object(transport,'entry_limit',return_value=1):
            root=Path(tmp);archive=self.archive(root)
            with self.assertRaises(ValueError):transport.extract(archive,root/'new')

    def test_real_compressed_payload_rejected_by_actual_receipt_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); archive=root/'bomb.zip'
            with zipfile.ZipFile(archive,'w',compression=zipfile.ZIP_DEFLATED) as stream:
                stream.writestr('receipt.json',b'0'*(transport.prepared.MAX_RECEIPT+1))
                stream.writestr('base.qcow2',b'base')
                stream.writestr('pool/fedora-44.asc',b'key')
            self.assertLess(archive.stat().st_size,10000)
            with self.assertRaises(ValueError): transport.extract(archive,root/'new')
            self.assertFalse((root/'new').exists())

    def test_invalid_truncated_and_bad_crc_archives(self):
        for damage in ('invalid','truncated','crc'):
            with self.subTest(damage=damage),tempfile.TemporaryDirectory() as tmp, mock.patch.object(Path,'chmod'):
                root=Path(tmp); archive=self.archive(root); raw=archive.read_bytes()
                if damage=='invalid': raw=b'not a zip'
                elif damage=='truncated': raw=raw[:-40]
                else: raw=raw.replace(b'bytes',b'bytex',1)
                archive.write_bytes(raw)
                with self.assertRaises(zipfile.BadZipFile): transport.extract(archive,root/'new')

    def test_failure_codes_never_include_secrets(self):
        for status,expected in ((403,'read_permission_denied'),(404,'artifact_missing_or_expired'),
                                (410,'artifact_missing_or_expired'),(500,'artifact_http_failure')):
            error=urllib.error.HTTPError('https://secret',status,'secret',{},None)
            self.assertEqual(transport.error_code(error),expected)
        self.assertEqual(transport.error_code(transport.TransportError('metadata_mismatch')),'metadata_mismatch')
        self.assertEqual(transport.error_code(transport.TransportError('receipt_mismatch_rebuild_required')),'receipt_mismatch_rebuild_required')
        self.assertEqual(transport.error_code(TimeoutError('secret')),'transport_timeout')
        self.assertEqual(transport.error_code(ValueError('secret')),'artifact_validation_failed')

    def test_extract_never_adopts_existing_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);archive=self.archive(root);output=root/'existing';output.mkdir();(output/'human').write_text('keep')
            with self.assertRaises(ValueError):transport.extract(archive,output)
            self.assertEqual((output/'human').read_text(),'keep')

    def test_signed_redirect_is_https_allowlisted_no_credentials(self):
        self.assertEqual(transport.signed_blob_url('https://example.blob.core.windows.net/artifact?q=signed'),
                         'https://example.blob.core.windows.net/artifact?q=signed')
        for value in ('http://example.blob.core.windows.net/x','https://evil.test/x',
                'https://user@example.blob.core.windows.net/x','https://example.blob.core.windows.net:444/x',
                'https://example.blob.core.windows.net/x#fragment'):
            with self.assertRaises(ValueError):transport.signed_blob_url(value)

    def response(self,data,status=200):
        response=io.BytesIO(data);response.status=status
        return response

    def test_download_never_sends_api_token_to_blob(self):
        url='https://example.blob.core.windows.net/artifact?q=signed'
        redirect=urllib.error.HTTPError('api',302,'redirect',{'Location':url},io.BytesIO())
        opener=mock.Mock();opener.open.side_effect=[redirect,self.response(b'archive')]
        with tempfile.TemporaryDirectory() as tmp:
            transport.download(opener,self.chosen,'secret',Path(tmp)/'zip',hashlib.sha256(b'archive').hexdigest(),7)
        requests=[call.args[0] for call in opener.open.call_args_list]
        self.assertEqual(requests[0].get_header('Authorization'),'Bearer secret')
        self.assertIsNone(requests[1].get_header('Authorization'))
        self.assertEqual(requests[1].full_url,url)

    def test_download_wrong_hash_size_and_second_redirect_fail(self):
        for size,digest in ((6,hashlib.sha256(b'archive').hexdigest()),(7,'0'*64)):
            redirect=urllib.error.HTTPError('api',302,'redirect',{'Location':'https://example.blob.core.windows.net/a'},io.BytesIO())
            opener=mock.Mock();opener.open.side_effect=[redirect,self.response(b'archive')]
            with tempfile.TemporaryDirectory() as tmp,self.assertRaises(ValueError):
                transport.download(opener,self.chosen,'secret',Path(tmp)/'zip',digest,size)
        self.assertIsNone(transport.NoRedirect().redirect_request(None,None,302,'x',{},'https://evil'))

    def test_extract_time_budget_and_entry_bound_fail_before_publication(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); archive=self.archive(root)
            with mock.patch.object(transport.time,'monotonic',side_effect=[0,301]):
                with self.assertRaises(ValueError): transport.extract(archive,root/'new')
            self.assertFalse((root/'new').exists())
            with mock.patch.object(transport,'MAX_ENTRIES',1):
                with self.assertRaises(ValueError): transport.extract(archive,root/'new')
            self.assertFalse((root/'new').exists())

    def test_download_time_budget_has_no_retry(self):
        redirect=urllib.error.HTTPError('api',302,'redirect',{'Location':'https://example.blob.core.windows.net/a'},io.BytesIO())
        opener=mock.Mock();opener.open.side_effect=[redirect,self.response(b'archive')]
        with tempfile.TemporaryDirectory() as tmp,mock.patch.object(transport.time,'monotonic',side_effect=[0,301]):
            with self.assertRaises(ValueError):transport.download(opener,self.chosen,'secret',Path(tmp)/'zip','c'*64,7)
        self.assertEqual(opener.open.call_count,2)

    def test_fetch_full_mock_flow_and_receipt_mismatch(self):
        for mismatch in (False,True):
            with self.subTest(mismatch=mismatch),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);output=root/'output'
                def extract(archive,staging):
                    staging.mkdir();(staging/'base.qcow2').write_bytes(b'base');(staging/'receipt.json').write_bytes(b'receipt');(staging/'pool').mkdir()
                receipt={'producer':{'commit':'d'*40 if mismatch else 'a'*40,'run_id':'123'}}
                with mock.patch.dict(os.environ,{'GITHUB_REPOSITORY':transport.REPOSITORY}),\
                     mock.patch.object(transport.urllib.request,'build_opener'),\
                     mock.patch.object(transport,'json_api',side_effect=[self.run,self.artifact]),\
                     mock.patch.object(transport,'download') as download,\
                     mock.patch.object(transport,'extract',side_effect=extract),\
                     mock.patch.object(transport.prepared,'select',return_value=receipt):
                    if mismatch:
                        with self.assertRaises(ValueError):transport.fetch(self.chosen,output,root,'secret')
                        self.assertFalse(output.exists())
                    else:
                        transport.fetch(self.chosen,output,root,'secret')
                        self.assertTrue((output/'base.qcow2').exists())
                    download.assert_called_once()

    def test_wrong_metadata_prevents_download(self):
        with tempfile.TemporaryDirectory() as tmp,mock.patch.dict(os.environ,{'GITHUB_REPOSITORY':transport.REPOSITORY}),\
                mock.patch.object(transport.urllib.request,'build_opener'),\
                mock.patch.object(transport,'json_api',side_effect=[{**self.run,'head_sha':'d'*40},self.artifact]),\
                mock.patch.object(transport,'download') as download:
            with self.assertRaises(ValueError):transport.fetch(self.chosen,Path(tmp)/'new',Path(tmp),'secret')
            download.assert_not_called()


if __name__ == '__main__': unittest.main()
