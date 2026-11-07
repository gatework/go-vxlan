#!/usr/bin/env python3
"""Run the native binary from the verified archive without rebuilding."""
import json, os, platform, subprocess, sys, tarfile, tempfile
from pathlib import Path
version = sys.argv[2].removeprefix('v')
system = {'Linux':'linux','Darwin':'darwin'}[platform.system()]
arch = {'x86_64':'amd64','aarch64':'arm64','arm64':'arm64'}[platform.machine()]
name = f'vxlan_{version}_{system}_{arch}'
with tempfile.TemporaryDirectory() as directory:
    temp = Path(directory)
    with tarfile.open(Path(sys.argv[1])/(name+'.tar.gz')) as archive:
        binary = temp/'vxlan'
        binary.write_bytes(archive.extractfile(name+'/vxlan').read())
    binary.chmod(0o700)
    env = dict(os.environ, HOME=str(temp), XDG_CONFIG_HOME=str(temp))
    def run(*args):
        return subprocess.check_output([str(binary),*args],cwd=temp,env=env,text=True,timeout=10)
    assert run('--version').strip() == version
    (temp/'sample.cfg').write_text('hostname LEAF\n')
    result = json.loads(run('parse','--file','sample.cfg','--complete','--json'))
    assert result['status']=='complete' and result['records'][0]['hostname']=='LEAF'
print('package smoke passed: '+name)
