"""Shared lightweight binding preserves the full Library's exact contract."""
import unittest
from uas import library, library_binding as binding


class LibraryBindingTests(unittest.TestCase):
    def project(self):
        return {'id':'alpha','repository':'owner/repository','roots':{'reference':'/owned/reference'}}

    def test_full_contract_reexports_one_validator_and_error_identity(self):
        for name in ('LibraryError','_fail','_token','_identifier','_absolute','project_binding',
                     'TOKEN','IDENTIFIER','REPOSITORY'):
            self.assertIs(getattr(library,name),getattr(binding,name))
        value=binding.project_binding(self.project(),source_identity='123')
        self.assertEqual(value,{'project_id':'alpha','project_identity':'github.com/123',
            'project_path':'github.com/owner/repository','reference_root':'/owned/reference/library',
            'snapshot_path':'/owned/reference/library.snapshot.json'})
        renamed=binding.project_binding({**self.project(),'repository':'owner/renamed'},source_identity='123')
        self.assertEqual(renamed['project_identity'],value['project_identity'])
        self.assertNotEqual(renamed['project_path'],value['project_path'])
        self.assertEqual(library.project_binding(self.project(),source_identity='123'),value)
        error=binding.LibraryError('REFUSED','field',{'digest':'a'*64})
        self.assertEqual((error.code,error.field,error.evidence,str(error)),
                         ('REFUSED','field',{'digest':'a'*64},'REFUSED: field'))

    def test_binding_invalid_matrix_keeps_exact_safe_codes_and_fields(self):
        cases=[(None,'123','INVALID_BINDING','project'),
               ({**self.project(),'id':'UPPER'},'123','INVALID_IDENTIFIER','project.id'),
               ({**self.project(),'id':True},'123','INVALID_IDENTIFIER','project.id'),
               ({**self.project(),'repository':'bad/private/path'},'123','INVALID_BINDING','project.repository'),
               ({**self.project(),'roots':None},'123','INVALID_BINDING','project.roots.reference')]
        for path in ('/','relative','/a/../b','/a//b','/a/./b','/a/'):
            cases.append(({**self.project(),'roots':{'reference':path}},'123','INVALID_BINDING','project.roots.reference'))
        for source in ('',True,'secret token','a'*129):
            cases.append((self.project(),source,'INVALID_IDENTIFIER','source_identity'))
        for project,source,code,field in cases:
            for api in (binding,library):
                with self.subTest(project=project,source=source,api=api.__name__),self.assertRaises(library.LibraryError) as caught:
                    api.project_binding(project,source_identity=source)
                self.assertEqual((caught.exception.code,caught.exception.field),(code,field))

    def test_shared_helpers_keep_custom_token_bound_and_canonical_path(self):
        self.assertEqual(binding._token('a'*12,'custom',12),'a'*12)
        with self.assertRaisesRegex(library.LibraryError,'INVALID_IDENTIFIER: custom'):
            binding._token('a'*12,'custom',11)
        self.assertFalse(binding._absolute('/a//b'))
        self.assertTrue(binding._absolute('/a/b'))
