"""Pure reference/configuration contract. No credential files or native effects."""
import io
import json
from pathlib import Path
import unittest
from uas.config import load, ConfigError
from uas.runtime_provider import ProviderAuthReference, select_reference, require_reference


class RuntimeProviderTests(unittest.TestCase):
    def config(self):
        doc = json.loads((Path(__file__).parent/'fixtures/two-rooms.json').read_text())
        doc['deployment']['credentials'].append({'id':'subscription','kind':'runtime-provider'})
        provider = doc['deployment']['providers'][0]
        provider['auth'] = {'credential_ref':'subscription',
                            'method':'pi-oauth-json' if provider['runtime']=='pi' else 'claude-oauth-token'}
        return doc, provider

    def test_selected_reference_survives_reload_without_claiming_inference(self):
        doc, provider = self.config()
        first = load(io.StringIO(json.dumps(doc)))
        selected = next(p for p in first['deployment']['providers'] if p['id']==provider['id'])
        ref = select_reference(selected,selected['runtime'])
        self.assertEqual(ref,select_reference(provider,provider['runtime']))
        self.assertEqual(ref.credential_ref,'subscription')
        self.assertIn('/providers/subscription/',ref.path('/room/runtime'))
        self.assertNotIn('context',ref.path('/room/runtime'))
        self.assertEqual(first['rooms'][0]['seats'][0]['resolved']['inference_health'],'unknown')
        self.assertNotIn('token',ref.document())

    def test_forge_reference_cannot_enter_native_auth(self):
        doc, provider = self.config()
        provider['auth']['credential_ref']='alice-forge'
        with self.assertRaises(ConfigError):load(io.StringIO(json.dumps(doc)))

    def test_wrong_runtime_method_and_unknown_reference_rejected(self):
        for change in ({'method':'arbitrary-env'}, {'credential_ref':'missing'}, {'path':'/etc/secret'}):
            doc, provider = self.config(); provider['auth'].update(change)
            with self.assertRaises(ConfigError):load(io.StringIO(json.dumps(doc)))

    def test_absence_is_not_synthetic_authentication(self):
        self.assertIsNone(select_reference({'id':'claude','runtime':'claude'},'claude'))
        with self.assertRaises(ValueError):require_reference(None,'claude')
        with self.assertRaises(ValueError):require_reference(ProviderAuthReference('pi','pi','auth','pi-oauth-json'),'claude')

    def test_path_escape_or_method_switch_rejected(self):
        for ref in ('../actor','/secret','with space'):
            with self.assertRaises(ValueError):ProviderAuthReference('pi','pi',ref,'pi-oauth-json')
        with self.assertRaises(ValueError):ProviderAuthReference('pi','pi','auth','claude-oauth-token')


if __name__ == '__main__': unittest.main()
