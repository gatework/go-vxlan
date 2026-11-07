#!/usr/bin/env python3
"""隔离验证发布、部分失败恢复与回读门禁，不访问 GitHub。"""

import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

STUB = r'''#!/usr/bin/env python3
import base64,json,os,re,sys
from pathlib import Path
p=Path(os.environ['RELEASE_TEST_STATE']); s=json.loads(p.read_text()); a=sys.argv[1:]
def save(): p.write_text(json.dumps(s))
def stop(): save(); sys.exit(1)
def option(k): return a[a.index(k)+1]
s['calls'].append(a)
if a[0]=='api':
 if '/releases/tags/' in a[1] and s['draft']: stop()
 q=option('--jq')
 if s.get('api_error')==q: stop()
 if '/releases?' in a[1]:
  if s['exists']: print(42)
 elif q=='.id': print(42)
 elif q=='.draft': print(str(s['draft']).lower())
 elif q=='.tag_name': print(s.get('tag_name','v1.2.3'))
 elif q=='.prerelease': print(str(s.get('prerelease',False)).lower())
 elif q=='.assets[].name':
  for n in s['assets']: print(n)
 elif '@tsv' in q:
  match=re.search(r'select\(\.name == "([^"]+)"\)',q)
  for n,v in s['assets'].items():
   if match and match.group(1)!=n: continue
   print(str(v['id'])+'\t'+n+'\t'+str(len(base64.b64decode(v['data']))))
 else: stop()
elif a[:2]==['release','create']:
 if s['exists']: stop()
 s['exists']=True; s['draft']=True
elif a[:2]==['release','upload']:
 f=Path(a[3]); n=f.name
 if n in s['assets']: stop()
 s['assets'][n]={'id':100+len(s['assets']),'data':base64.b64encode(f.read_bytes()).decode()}
elif a[:2]==['release','download']:
 n=option('--pattern'); dest=Path(option('--dir'))/n
 if n not in s['assets']: stop()
 data=base64.b64decode(s['assets'][n]['data'])
 if s.get('bad_readback')==n: data+=b'corrupt'
 dest.write_bytes(data)
 if s.get('replace_during_read')==n: s['assets'][n]['id']+=1000
elif a[:2]==['release','edit']:
 if len(s['assets'])!=5: stop()
 s['draft']=False
 if s.get('change_metadata'): s['tag_name']='v9.9.9'
else: stop()
save()
'''

GIT_STUB = r'''#!/usr/bin/env python3
import json,os,sys
from pathlib import Path
p=Path(os.environ['RELEASE_TEST_STATE']); s=json.loads(p.read_text())
if sys.argv[1:] == ['rev-parse','HEAD']: print(os.environ['GITHUB_SHA'])
else:
 s['tag_reads']=s.get('tag_reads',0)+1
 sha=os.environ['GITHUB_SHA']
 if s.get('wrong_tag') or (s.get('changed_tag') and s['tag_reads']>1): sha='b'*40
 print(sha+'\trefs/tags/v1.2.3')
 p.write_text(json.dumps(s))
'''


class PublishReleaseTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'scripts').mkdir()
        shutil.copy(Path(__file__).with_name('publish-release.sh'), self.root / 'scripts')
        (self.root / 'docs/releases').mkdir(parents=True)
        (self.root / 'docs/releases/v1.2.3.md').write_text('release notes\n')
        (self.root / 'dist').mkdir()
        names = ['vxlan_1.2.3_' + p + '.tar.gz' for p in
                 ['linux_amd64', 'linux_arm64', 'darwin_amd64', 'darwin_arm64']]
        self.files = {n: n.encode() for n in names}
        self.files['SHA256SUMS'] = ''.join(
            hashlib.sha256(b).hexdigest() + '  ./' + n + '\n'
            for n, b in self.files.items()).encode()
        for n, b in self.files.items():
            (self.root / 'dist' / n).write_bytes(b)
        (self.root / 'bin').mkdir()
        stub = self.root / 'bin/gh'
        stub.write_text(STUB)
        stub.chmod(0o755)
        git = self.root / 'bin/git'
        git.write_text(GIT_STUB)
        git.chmod(0o755)
        self.state = self.root / 'state.json'
        self.initial = {'exists': False, 'draft': True, 'assets': {}, 'calls': []}

    def existing(self, names=None, draft=True):
        self.initial['exists'] = True
        self.initial['draft'] = draft
        for i, n in enumerate(self.files if names is None else names):
            self.initial['assets'][n] = {'id': i + 1, 'data': base64.b64encode(self.files[n]).decode()}

    def run_script(self, expected=0):
        self.state.write_text(json.dumps(self.initial))
        env = dict(os.environ, PATH=str(self.root / 'bin') + os.pathsep + os.environ['PATH'],
                   GITHUB_REPOSITORY='owner/repo', GITHUB_REF_NAME='v1.2.3',
                   GITHUB_REF_TYPE='tag', RELEASE_TEST_STATE=str(self.state))
        env['GITHUB_SHA'] = 'a' * 40
        result = subprocess.run(['sh', 'scripts/publish-release.sh'], cwd=self.root,
                                env=env, capture_output=True, text=True, timeout=15)
        if expected == 0:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0)
        return json.loads(self.state.read_text())

    def writes(self, s):
        return [a for a in s['calls'] if a[:2] in
                [['release', 'create'], ['release', 'upload'], ['release', 'edit']]]

    def test_fresh_publish_and_rerun(self):
        s = self.run_script()
        self.assertFalse(s['draft'])
        self.assertEqual(len(s['assets']), 5)
        self.assertEqual(sum(a[:2] == ['release', 'download'] for a in s['calls']), 5)
        self.initial = dict(s, calls=[])
        s = self.run_script()
        self.assertEqual(self.writes(s), [])

    def test_partial_draft_uploads_only_missing(self):
        self.existing(['SHA256SUMS'])
        s = self.run_script()
        self.assertEqual(sum(a[:2] == ['release', 'upload'] for a in s['calls']), 4)
        self.assertFalse(s['draft'])

    def test_existing_mismatch_is_not_overwritten(self):
        self.existing()
        self.initial['assets']['SHA256SUMS']['data'] = base64.b64encode(b'wrong').decode()
        s = self.run_script(1)
        self.assertEqual(self.writes(s), [])

    def test_api_failure_does_not_create_release(self):
        self.initial['api_error'] = '.[] | select(.tag_name == "v1.2.3") | .id'
        self.assertEqual(self.writes(self.run_script(1)), [])

    def test_asset_api_failure_does_not_upload(self):
        self.existing(['SHA256SUMS'])
        self.initial['api_error'] = '.assets[].name'
        self.assertEqual(self.writes(self.run_script(1)), [])

    def test_corrupt_download_keeps_draft(self):
        self.initial['bad_readback'] = 'SHA256SUMS'
        self.assertTrue(self.run_script(1)['draft'])

    def test_replaced_asset_keeps_draft(self):
        self.initial['replace_during_read'] = 'SHA256SUMS'
        self.assertTrue(self.run_script(1)['draft'])

    def test_unexpected_asset_is_rejected(self):
        self.existing()
        self.initial['assets']['extra'] = {'id': 99, 'data': ''}
        self.assertEqual(self.writes(self.run_script(1)), [])

    def test_incomplete_published_release_is_not_modified(self):
        self.existing(['SHA256SUMS'], draft=False)
        self.assertEqual(self.writes(self.run_script(1)), [])

    def test_wrong_release_tag_stops_before_mutation(self):
        self.existing()
        self.initial['tag_name'] = 'v9.9.9'
        self.assertEqual(self.writes(self.run_script(1)), [])

    def test_prerelease_stops_before_mutation(self):
        self.existing(draft=False)
        self.initial['prerelease'] = True
        self.assertEqual(self.writes(self.run_script(1)), [])

    def test_final_metadata_change_fails(self):
        self.initial['change_metadata'] = True
        self.run_script(1)

    def test_wrong_tag_stops_before_mutation(self):
        self.initial['wrong_tag'] = True
        self.assertEqual(self.writes(self.run_script(1)), [])

    def test_changed_tag_keeps_draft(self):
        self.initial['changed_tag'] = True
        self.assertTrue(self.run_script(1)['draft'])


if __name__ == '__main__':
    unittest.main()
