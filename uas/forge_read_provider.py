"""External Broker's single pinned GitHub provider; never Actor-selected host."""
import json
import re

from .github_read import GitHubProject, ProviderResponse, _unique
from .github_logs import CompletedJobLogProvider
from .github_surface import GitHubSurfaceProvider


class BrokerReadProvider:
    host = 'github.com'
    def __init__(self, project, transport, log_transport):
        if type(project) is not GitHubProject: raise ValueError('fixed Project required')
        self.project, self.transport, self.log_transport = project, transport, log_transport
        self.surface = GitHubSurfaceProvider(project, transport)

    def read_admission(self, number):
        """Canonical bounded eligibility facts, not the generic display surface."""
        from .github_read import GitHubReadProvider, validate_observation
        return validate_observation(GitHubReadProvider(self.project, self.transport.get).read_issue(
            number, admission=True))

    def read(self, route):
        if route.kind != 'job-log': return self.surface.read(route)
        if route.repository.lower() != self.project.repository.lower():
            return {'status': 'PROJECT_MISMATCH', 'completeness': 'unknown'}
        # Ordinary native gh log reads select a run/job, not a Hub Gate candidate.
        # Derive the exact selected run SHA externally then independently reread
        # and validate it inside the log provider. No caller-supplied SHA/URL.
        from types import MappingProxyType
        from .github_routes import SurfaceRoute
        from .github_logs import validate_log_observation
        try:
            scope = self.surface.read(SurfaceRoute('run-view', route.repository, route.number,
                MappingProxyType({key:value for key,value in route.options.items() if key != 'log'})))
            if scope['status'] != 'OK' or scope['completeness'] != 'complete':
                return {'status': scope['status'], 'completeness': scope['completeness']}
            run, job = scope['data']['run'], scope['data']['job']
            run_id, job_id, attempt, sha = run['id'], job['id'], run['run_attempt'], run['head_sha']
            if job_id != route.options['job']:
                raise ValueError()
            result = CompletedJobLogProvider(self.project, self.transport, self.log_transport).read(
                run_id, job_id, attempt, sha)
            return validate_log_observation(result,self.project,run_id,job_id,attempt,sha)
        except Exception:
            return {'status': 'INVALID_LOG_SCOPE', 'completeness': 'unknown'}
