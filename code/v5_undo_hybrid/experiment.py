"""Only the supplied execution functions; obsolete source-rewriting builders removed."""
from concurrent.futures import ThreadPoolExecutor
import argparse
import difflib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
HERE=Path(__file__).resolve().parent; ROOT=HERE.parent; NS3=Path("/home/ubuntu/ns-3.48")
def sha(path):
    with Path(path).open("rb") as f: return hashlib.file_digest(f,"sha256").hexdigest()
MODES=()
def event(city):return json.loads((HERE/f'{city}_event.json').read_text())

def config(city):
    e=event(city);text=(ROOT/'runs/ny_baseline_q100_60s/config_ns3.properties').read_text()
    changes={'simulation_end_time_ns':str(round(e['stop_s']*1e9)),
        'satellite_network_dir':'"../../..'+e['native_state']+'"',
        'satellite_network_routes_dir':'"../../..'+e['native_state']+'/dynamic_state_100ms_for_200s"'}
    return '\n'.join(line.split('=',1)[0]+'='+changes[line.split('=',1)[0]] if line.split('=',1)[0] in changes else line for line in text.splitlines())+'\n'

def run(case):
    city,arm=case.split(':');assert arm in MODES
    e=event(city);plan=json.loads((HERE/'frozen_plan.json').read_text());build=plan['build']
    binary=NS3/'build/scratch/main_satnet/ns3.48-main_satnet'
    assert sha(binary)==build['binary_sha256'] and sha(NS3/'build/lib/libns3.48-internet.so')==build['internet_sha256']
    assert all(sha(NS3/f)==digest for f,digest in build['sources'].items())
    assert sha(HERE/f'{city}_event.txt')==plan['events'][city]
    native_root=Path('/tmp')/('lab1-undo-'+build['binary_sha256'][:12]);native=native_root/(city+'_'+arm)
    dest=HERE/'runs'/(city+'_'+arm);assert not dest.exists() and not native.exists(),'Never overwrite evidence'
    dest.mkdir(parents=True);native.mkdir(parents=True)
    (native/'config_ns3.properties').write_text(config(city));shutil.copyfile(ROOT/'runs/ny_baseline_q100_60s/schedule.csv',native/'schedule.csv')
    mode='baseline' if arm in ('baseline','undo','undo_full') else 'adaptive'
    env=dict(os.environ,HYBRID_ARM=arm,HYBRID_FULL_UNDO='1' if arm=='undo_full' else '0',ADAPT_MODE=mode,
        ADAPT_EVENT_FILE=str(HERE/f'{city}_event.txt'),ADAPT_NOMINAL_NS=str(e['nominal_ns']),LAB1_DIAG='1',LAB1_HOPS='1',LAB1_EARLY_RTO='1')
    manifest=dict(case=case,city=city,arm=arm,build=build,event_sha256=plan['events'][city],
        config_sha256=sha(native/'config_ns3.properties'),schedule_sha256=sha(native/'schedule.csv'),
        environment={k:v for k,v in env.items() if k.startswith(('HYBRID_','ADAPT_','LAB1_'))})
    (dest/'manifest.json').write_text(json.dumps(manifest,indent=2));print('START',case,flush=True);start=time.monotonic()
    with (dest/'console.log').open('w') as stream:
        p=subprocess.run([str(binary),'--run_dir='+str(native)],cwd=NS3,env=env,stdout=stream,stderr=subprocess.STDOUT)
    shutil.copytree(native,dest,dirs_exist_ok=True);manifest.update(exit_code=p.returncode,wall_seconds=time.monotonic()-start)
    (dest/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    assert p.returncode==0 and (dest/'logs_ns3/finished.txt').read_text().strip()=='Yes',case
    assert native.resolve().is_relative_to(native_root)
    for f in native.rglob('*'):
        if f.is_file():assert sha(f)==sha(dest/f.relative_to(native))
    shutil.rmtree(native);print('DONE',case,round(manifest['wall_seconds'],1),flush=True)
