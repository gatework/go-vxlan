#!/usr/bin/env python3
"""Exercise artifact provenance and failure handling offline using the real jq filters."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import zipfile

SHA = 'a' * 40
STUB = r'''#!/usr/bin/env python3
import json,os,subprocess,sys
from pathlib import Path
state=json.loads(Path(os.environ['REUSE_STATE']).read_text())
a=sys.argv[1:]; endpoint=a[1]
with Path(os.environ['REUSE_CALLS']).open('a') as f: f.write(endpoint+'\n')
if state.get('api_error') in endpoint: sys.exit(1)
if endpoint.endswith('/zip'):
 if endpoint!='repos/owner/repo/actions/artifacts/73/zip': sys.exit(1)
 sys.stdout.buffer.write(Path(os.environ['REUSE_ZIP']).read_bytes());sys.exit()
if endpoint.endswith('/ci.yml'): data={'id':state.get('workflow_id',7)}
elif '/workflows/7/runs?' in endpoint: data={'workflow_runs':state['runs']}
elif endpoint.endswith('/runs/42/artifacts'): data={'artifacts':state['artifacts']}
else: sys.exit(1)
result=subprocess.run(['jq','-r',a[a.index('--jq')+1]],input=json.dumps(data),text=True)
sys.exit(result.returncode)
'''

class ReuseReleaseTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root/'scripts').mkdir()
        shutil.copy(Path(__file__).with_name('reuse-release.sh'), self.root/'scripts')
        (self.root/'scripts/verify-release.sh').write_text('test -s "$1/payload"\ntest "$2" = v1.2.3\ntest "$3" = '+SHA+'\n')
        (self.root/'bin').mkdir()
        for name, text in [('gh',STUB),('git','#!/bin/sh\nprintf "%s\\n" "$GITHUB_SHA"\n')]:
            path=self.root/'bin'/name;path.write_text(text);path.chmod(0o755)
        self.archive=self.root/'artifact.zip'
        with zipfile.ZipFile(self.archive,'w') as archive: archive.writestr('payload','CI bytes')
        self.run={'id':42,'head_sha':SHA,'head_branch':'main','event':'push','workflow_id':7,'status':'completed','conclusion':'success'}
        self.artifact={'id':73,'name':'source-'+SHA,'expired':False,'size_in_bytes':100}
        self.state={'runs':[self.run],'artifacts':[self.artifact], 'api_error':'never-match'}

    def execute(self, success=True):
        path=self.root/'state.json';path.write_text(json.dumps(self.state))
        calls=self.root/'calls'
        env=dict(os.environ,PATH=str(self.root/'bin')+os.pathsep+os.environ['PATH'],GITHUB_SHA=SHA,
                 GITHUB_REF_TYPE='tag',GITHUB_REF_NAME='v1.2.3',GITHUB_REPOSITORY='owner/repo',
                 REUSE_STATE=str(path),REUSE_CALLS=str(calls),REUSE_ZIP=str(self.archive))
        result=subprocess.run(['sh','scripts/reuse-release.sh'],cwd=self.root,env=env,capture_output=True,text=True,timeout=10)
        if success:
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            self.assertIn('/artifacts/73/zip',calls.read_text())
            self.assertEqual((self.root/'dist/payload').read_text(),'CI bytes')
        else: self.assertNotEqual(result.returncode,0,result.stdout+result.stderr)

    def test_invalid_workflow_id(self): self.state['workflow_id']='7 or true';self.execute(False)
    def test_missing_workflow_id(self): self.state['workflow_id']=None;self.execute(False)
    def test_push(self): self.execute()
    def test_main_manual_ci(self): self.run['event']='workflow_dispatch';self.execute()
    def test_untrusted_runs(self):
        for key,value in [('head_sha','b'*40),('head_branch','feature'),('event','pull_request'),('workflow_id',9),('conclusion','failure'),('status','in_progress')]:
            with self.subTest(key=key):
                old=self.run[key];self.run[key]=value;self.execute(False);self.run[key]=old
    def test_no_run(self): self.state['runs']=[];self.execute(False)
    def test_expired(self): self.artifact['expired']=True;self.execute(False)
    def test_empty(self): self.artifact['size_in_bytes']=0;self.execute(False)
    def test_missing(self): self.state['artifacts']=[];self.execute(False)
    def test_duplicate(self): self.state['artifacts']*=2;self.execute(False)
    def test_wrong_name(self): self.artifact['name']='source-other';self.execute(False)
    def test_api_error(self): self.state['api_error']='/artifacts';self.execute(False)
    def test_zip_error(self): self.state['api_error']='/zip';self.execute(False)
    def test_verification_error(self): (self.root/'scripts/verify-release.sh').write_text('exit 1\n');self.execute(False)

if __name__ == '__main__': unittest.main()
