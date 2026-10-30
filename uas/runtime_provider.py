"""Installation-selected Runtime auth references, never credential contents.

This module performs no file reads, provisioning or inference. The fixed native
entry reads the human-provisioned file inside the existing Runtime mount. These
provider credentials are Room-local accepted exposure, unlike Actor/Forge keys.
"""
from dataclasses import dataclass
import re

METHODS = {'claude': ('claude-oauth-token',), 'pi': ('pi-oauth-json',)}
ID = re.compile(r'[a-z][a-z0-9-]{0,63}\Z')


@dataclass(frozen=True)
class ProviderAuthReference:
    runtime: str
    provider_id: str
    credential_ref: str
    method: str

    def __post_init__(self):
        if (type(self.runtime) is not str or self.runtime not in METHODS
                or any(type(x) is not str or not ID.fullmatch(x)
                       for x in (self.provider_id, self.credential_ref))
                or type(self.method) is not str or self.method not in METHODS[self.runtime]):
            raise ValueError('invalid Runtime provider reference')

    def path(self, runtime_root):
        from .native_pi_recipe import path
        return path(runtime_root) + '/providers/' + self.credential_ref + ('/auth.json' if self.runtime == 'pi' else '/token')

    def document(self):
        return dict(runtime=self.runtime, provider_id=self.provider_id,
                    credential_ref=self.credential_ref, method=self.method)


def select_reference(provider, runtime, *, native_provider=None):
    """Consume only a provider already validated by installation config.load."""
    if provider['runtime'] != runtime:
        raise ValueError('Runtime provider mismatch')
    auth = provider.get('auth')
    if auth is None:
        return None  # Legacy/offline fixtures retain their explicit no-auth state.
    result = ProviderAuthReference(runtime, provider['id'], auth['credential_ref'], auth['method'])
    return result


def require_reference(reference, runtime):
    if type(reference) is not ProviderAuthReference or reference.runtime != runtime:
        raise ValueError('selected Runtime provider authentication unavailable')
    return reference
