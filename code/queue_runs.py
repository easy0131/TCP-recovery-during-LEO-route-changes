"""Rerun the London 60-second queue sweep with all handover controls disabled."""
import argparse
import csv
import json
from pathlib import Path
import shutil
import subprocess
import sys
from zipfile import ZipFile, ZIP_DEFLATED
import reproduce as r

ROOT = Path(__file__).resolve().parent
OUT = ROOT / 'generated/queues'
QUEUES = (100, 250, 500, 1000)

def run():
    r.prepare(['london'])
    built = r.read(r.OUT / 'build_provenance.json')
    for q in QUEUES:
        here = OUT / f'q{q}'
        dest = here / 'runs/london_baseline'
        if dest.exists():
            m = r.read(dest / 'manifest.json')
            assert m['exit_code'] == 0 and m['build'] == built
            assert (dest/'logs_ns3/finished.txt').read_text().strip() == 'Yes'
            print('KEEP completed queue run', q, flush=True)
            continue
        here.mkdir(parents=True, exist_ok=True)
        event = r.read(r.event_dir('london')/'london_event.json')
        event['stop_s'] = 60
        (here/'london_event.json').write_text(json.dumps(event,indent=2)+'\n')
        shutil.copyfile(r.event_dir('london')/'london_event.txt',here/'london_event.txt')
        (here/'frozen_plan.json').write_text(json.dumps(dict(build=built, events={'london':r.sha(here/'london_event.txt')}),indent=2)+'\n')
        exp = r.module('queue_execution', ROOT/'v5_undo_hybrid/experiment.py')
        exp.HERE = here
        exp.MODES = ('baseline',)
        original = exp.config
        def config(city):
            text = original(city)
            for key in ('isl_max_queue_size_pkts', 'gsl_max_queue_size_pkts'):
                old = key+'=100\n'
                assert text.count(old) == 1
                text = text.replace(old,key+'='+str(q)+'\n')
            return text
        exp.config = config
        exp.run('london:baseline')

def analyze():
    a = r.module('queue_analysis',ROOT/'v5_undo_hybrid/analyze.py')
    items = []
    evidence = []
    built = r.read(r.OUT/'build_provenance.json')
    names = ['config_ns3.properties','logs_ns3/finished.txt','logs_ns3/tcp_flows.csv'] + ['logs_ns3/tcp_flow_0_'+k+'.csv' for k in ['cwnd','rtt','progress']]
    for q in QUEUES:
        here = OUT/f'q{q}'; folder = here/'runs/london_baseline'
        m = r.read(folder/'manifest.json')
        assert m['build'] == built and m['exit_code'] == 0
        assert m['environment']['HYBRID_ARM'] == m['environment']['ADAPT_MODE'] == 'baseline'
        assert m['environment']['HYBRID_FULL_UNDO'] == '0'
        for filename,key in [('config_ns3.properties','config_sha256'),('schedule.csv','schedule_sha256')]:
            assert r.sha(folder/filename)==m[key]
        event = r.read(here/'london_event.json')
        assert event['stop_s']==60 and m['event_sha256']==r.sha(here/'london_event.txt')
        trace = a.p.load(folder=folder)
        control = a.v5.controller(trace,'baseline',event,100)
        proof,_ = a.packet_proof(trace,event)
        undo = a.undo_checks(trace,'baseline',event,proof)
        assert not control['pacing_used'] and control['actual_start_s'] is None
        assert not any(undo[k] for k in ['arm','begin','apply','reject','windows'])
        evidence.append(dict(queue=q,rtos=trace['rtos'],tc_drops=len([x for x in trace['drops'] if x['event']=='TcDrop']),
                             trace_sha256={name:r.sha(folder/name) for name in r.TRACE_FILES}))
        archive = OUT/f'q{q}_analysis_input.zip'
        with ZipFile(archive,'w',ZIP_DEFLATED) as z:
            for name in names: z.write(folder/name, f'runs/q{q}/'+name)
        items.append(dict(queue=q,run=f'q{q}',archive=f'q{q}_analysis_input.zip'))
        del trace
    md = OUT/'analysis/manifest.json';md.parent.mkdir(exist_ok=True)
    md.write_text(json.dumps(dict(runs=items,windows_s=[[0,60],[0,5],[5,20],[20,60]]),indent=2)+'\n')
    (OUT/'diagnostics.json').write_text(json.dumps(evidence,indent=2)+'\n')
    subprocess.run([sys.executable,str(ROOT/'analyze_queue_delay.py'),'--manifest',str(md),'--out',str(OUT/'analysis/generated')],check=True)
    expected = r.read(ROOT/'queue_reference.json')['results']
    current = r.read(OUT/'analysis/generated/results.json')['results']
    # Compare only common declared windows; do not substitute old numbers on a mismatch.
    old = {(x['queue'],x['start_s'],x['end_s']):x for x in expected}
    mismatches=[]
    for row in current:
        key=(row['queue'],row['start_s'],row['end_s'])
        if key not in old: continue
        for field in ['ack_mbps','srtt_p50_ms','srtt_p95_ms','srtt_mean_ms']:
            if abs(row[field]-old[key][field]) > 1e-8:
                mismatches.append(dict(key=key,field=field,reference=old[key][field],current=row[field]))
    (OUT/'reference_check.json').write_text(json.dumps(dict(matches=not mismatches,mismatches=mismatches),indent=2)+'\n')
    assert not mismatches, 'New queue metrics differ: inspect generated/queues/reference_check.json'
    print('PASS queue controls, logs and historical queue metrics',flush=True)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=['run','analyze']);args=p.parse_args();globals()[args.action]()
