"""Resumable candidate pipeline. Existing failed runs are kept for inspection."""
import argparse
from pathlib import Path
import subprocess
import sys
import reproduce as r
ROOT=Path(__file__).resolve().parent

def command(script,*args):
    plotting = script == 'render_results.py' or (script == 'queue_runs.py' and args == ('analyze',))
    prefix = ['uv', 'run', '--frozen', 'python'] if plotting else [sys.executable]
    subprocess.run([*prefix,str(ROOT/script),*args],cwd=ROOT,check=True)

def missing(folder,city,arm):
    p=folder/'experiment/runs'/f'{city}_{arm}'
    if not p.exists(): return True
    m=r.read(p/'manifest.json')
    assert m['exit_code']==0 and (p/'logs_ns3/finished.txt').read_text().strip()=='Yes', 'Incomplete run preserved: '+str(p)
    return False

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--smoke',action='store_true');args=p.parse_args()
    command('reproduce.py','verify')
    subprocess.run(['uv','sync','--frozen'],cwd=ROOT,check=True)
    command('reproduce.py','build')
    cities=['london'] if args.smoke else list(r.CITIES)
    arms=['queue_guard_undo'] if args.smoke else list(r.ARMS)
    command('candidate_support.py','states',*cities)
    cases=[c+':'+a for c in cities for a in arms if missing(ROOT/'reproduced',c,a)]
    if cases:command('reproduce.py','run',*cases)
    cities_left=[c for c in cities if missing(ROOT/'reproduced_baseline',c,'baseline')]
    if cities_left:command('reproduce_baseline.py','run',*cities_left)
    command('reproduce_baseline.py','analyze')
    command('render_results.py')
    command('diagnose.py')
    if not args.smoke:
        command('queue_runs.py','run')
        command('queue_runs.py','analyze')
    print('PASS candidate workflow', 'SMOKE (not full validation)' if args.smoke else '42 route cases + 4 queue cases',flush=True)

if __name__=='__main__':main()
