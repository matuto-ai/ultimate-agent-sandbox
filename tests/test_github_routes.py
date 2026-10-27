import unittest
from uas.github_read import GitHubProject
from uas.github_routes import _ROUTES, help_text, parse_read_route
from uas.ledger import LedgerError


class ReadRouteTests(unittest.TestCase):
    def setUp(self): self.project = GitHubProject('owner/repo')

    def test_table_is_discovery_and_enforcement_for_every_read_family(self):
        for kind, words, positional, flags in _ROUTES:
            argv = [*words]
            if positional: argv += ['src/main.py' if kind == 'repo-file' else '42']
            if kind == 'run-view': argv += ['42']
            route = parse_read_route(argv, self.project)
            self.assertEqual(kind, route.kind)
            self.assertIn('gh ' + ' '.join(words), help_text())
            self.assertEqual('other/repo', parse_read_route([*argv,'-R','other/repo'],self.project).repository)
        for group in {row[1][0] for row in _ROUTES}:
            self.assertEqual(1,help_text().count('\n'+group.upper()+':\n'))

    def test_only_same_forge_repository_selector_never_host_or_auth(self):
        for selected in ['https://evil.test/x/y','github.com/owner/repo','../repo','x/..','x/y?token=abc']:
            with self.subTest(selected=selected), self.assertRaises(LedgerError):
                parse_read_route(['issue','view','1','-R',selected],self.project)
        for argv in [['api','repos/owner/repo'],['auth','token'],['pr','merge','1'],['run','rerun','1'],
                     ['run','download','1'],['workflow','run','1'],['issue','view','1','--hostname','other'],
                     ['issue','view','1','--repo','owner/repo','-R','other/repo']]:
            with self.subTest(argv=argv), self.assertRaises(LedgerError): parse_read_route(argv,self.project)

    def test_job_logs_are_project_pinned_and_no_whole_run_or_live_mode(self):
        for argv in [['run','view','1','--log'],['run','view','1','--log-failed'],
                     ['run','view','1','--job','2','--log','-R','other/repo'],['run','watch','1']]:
            with self.assertRaises(LedgerError): parse_read_route(argv,self.project)
        route = parse_read_route(['run','view','1','--job','2','--log','--attempt','3'],self.project)
        self.assertEqual(('job-log',1,{'job':2,'log':True,'attempt':3}),(route.kind,route.number,dict(route.options)))
        self.assertIsNone(parse_read_route(['run','view','--job','2','--log'],self.project).number)

    def test_path_selectors_option_types_and_unicode_bounds(self):
        for path in ['/tmp/secrets','../x','a/../x','a//x','a\\b']:
            with self.assertRaises(LedgerError): parse_read_route(['repo','read-file',path],self.project)
        for argv in [['issue','view','-1'],['issue','view','01'],['issue','list','--limit','0'],
                     ['issue','list','--limit','1001'],['issue','list','--state','merged'],
                     ['repo','read-file','x','--ref','--exec'],['issue','view','1','--comments','--comments']]:
            with self.assertRaises(LedgerError): parse_read_route(argv,self.project)
        with self.assertRaises(LedgerError): parse_read_route(['issue','view','\ud800'],self.project)
        self.assertEqual('src/a.py',parse_read_route(['repo','read-file','src/a.py'],self.project).options['path'])
