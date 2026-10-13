"""Prospective Manila route, with the candidate fixed before any transport run."""
from concurrent.futures import ThreadPoolExecutor
import csv
import importlib.util
import json
import multiprocessing
import os
from pathlib import Path
import subprocess
import sys
import zipfile

PARENT=Path(__file__).resolve().parent
ROOT=PARENT.parent
HERE=PARENT/'manila'
STATE=Path('/tmp/lab1-seoul-manila-queue/state')
ARMS=('v5','undo','auto_watch_undo','guard_watch_undo','queue_guard_undo')

def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value

exp=module('manila_common',ROOT/'v5_undo_hybrid/experiment.py')

class ForkWorkers:
    """Use unchanged disjoint Hypatia worker intervals in separate processes."""
    def __init__(self,count):self.count=count
    def map(self,fn,items):
        assert len(items)==self.count
        workers=[multiprocessing.get_context('fork').Process(target=fn,args=(item,)) for item in items]
        for worker in workers:worker.start()
        for worker in workers:worker.join()
        assert all(worker.exitcode==0 for worker in workers),'Geometry worker failed'
    def close(self):pass
    def join(self):pass

def freeze():
    HERE.mkdir(exist_ok=False)
    parent=json.loads((PARENT/'frozen_plan.json').read_text())
    plan=dict(build=parent['build'],arms=ARMS,city='manila',ground_stations=parent['next_unseen_route']['stations'],
        selection=parent['next_unseen_route']['selection'],parent_plan_sha256=exp.sha(PARENT/'frozen_plan.json'),
        conditions=dict(link_mbps=100,queue_packets=100,flows=1,seed=123456789,initial_pacing=False),
        criteria='Candidate event10 >=99% of best v5/undo and previous guard; no whole loss/RTO increase vs v5 or previous guard; event10 retx zero; event2 LastRTT p95 <=110% of v5 and auto_watch_undo.',
        geometry='Original generator functions and 200s/100ms model; Hypatia disjoint interval workers run in forked processes instead of threads. Original files are unchanged.',
        generator_sha256=exp.sha(ROOT/'adaptive_handover_v5/gen_state_reference.py'))
    for name,digest in plan['build']['sources'].items():assert exp.sha(exp.NS3/name)==digest
    assert not STATE.exists()
    (HERE/'selection_plan.json').write_text(json.dumps(plan,indent=2)+'\n')
    print('MANILA PLAN FROZEN',flush=True)

def generate_worker():
    plan=json.loads((HERE/'selection_plan.json').read_text())
    gen=module('manila_generator',ROOT/'adaptive_handover_v5/gen_state_reference.py')
    helper=importlib.import_module('satgen.dynamic_state.helper_dynamic_state')
    helper.ThreadPool=ForkWorkers
    sys.argv=['gen_state',str(STATE.parent),'--duration','200','--step-ms','100','--threads','4']
    for station in plan['ground_stations']:sys.argv+=['--gs',station]
    gen.main()

def generate():
    assert not STATE.exists()
    with (HERE/'generation.log').open('w') as stream:
        subprocess.run(['python3',str(Path(__file__)),'generate_worker'],stdout=stream,stderr=subprocess.STDOUT,check=True)
    plan=json.loads((HERE/'selection_plan.json').read_text())
    prep=module('manila_prepare',ROOT/'adaptive_handover_v5/prepare.py');prep.HERE=HERE
    states,changes,digest=prep.v2.read_states(STATE,200)
    assert len(states)==2000
    choices=[(p,t,n) for p,t,n in zip([0]+changes[:-1],changes,changes[1:]+[200_000_000_000]) if t>=20e9 and t-p>=1e9 and n-t>=12e9]
    assert choices
    previous,t,nxt=choices[0]
    event=prep.make_event('manila',STATE,t,previous,nxt,states,digest)
    old=Path('/home/ubuntu/lab/data/seoul_london/state')
    assert all(exp.sha(STATE/f)==exp.sha(old/f) for f in ('tles.txt','isls.txt','description.txt','gsl_interfaces_info.txt'))
    with zipfile.ZipFile(HERE/'manila_state.zip','x',zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(STATE.rglob('*')):
            if path.is_file():archive.write(path,path.relative_to(STATE))
    plan.update(events={'manila':exp.sha(HERE/'manila_event.txt')},event_s=t/1e9,
        candidates_s=[t/1e9 for _,t,_ in choices],topology_changes_s=[t/1e9 for t in changes],
        selection_plan_sha256=exp.sha(HERE/'selection_plan.json'),state_sha256=exp.sha(HERE/'manila_state.zip'))
    (HERE/'frozen_plan.json').write_text(json.dumps(plan,indent=2)+'\n')
    print('MANILA INPUT FROZEN',event['nominal_s'],event['old_rtt_ns']/1e6,event['new_rtt_ns']/1e6,flush=True)

def run():
    exp.HERE=HERE;exp.MODES=tuple(set(exp.MODES)|set(ARMS))
    with ThreadPoolExecutor(max_workers=2) as pool:list(pool.map(exp.run,['manila:'+a for a in ARMS]))

def analyze():
    a=module('manila_analysis',ROOT/'v5_undo_hybrid/analyze.py')
    plan=json.loads((HERE/'frozen_plan.json').read_text());event=json.loads((HERE/'manila_event.json').read_text());t,end=event['nominal_s'],event['stop_s']
    base=a.p.load(folder=HERE/'runs'/'manila_v5')
    metrics=[];details=[]
    for arm in ARMS:
        folder=HERE/'runs'/('manila_'+arm);trace=base if arm=='v5' else a.p.load(folder=folder)
        manifest=json.loads((folder/'manifest.json').read_text())
        assert manifest['exit_code']==0 and manifest['build']==plan['build']
        assert manifest['event_sha256']==exp.sha(HERE/'manila_event.txt')==plan['events']['manila']
        for name,key in [('config_ns3.properties','config_sha256'),('schedule.csv','schedule_sha256')]:
            assert exp.sha(folder/name)==manifest[key] and (folder/name).read_bytes()==(base['folder']/name).read_bytes()
        a.v5.v1.same_prefix(trace,base,event['first_check_ns'])
        ctrl=a.v5.controller(trace,'baseline' if arm=='undo' else 'adaptive',event,100)
        for window,start,stop in [('event2',t,t+2),('event10',t,end),('whole',0,end),('aligned',t-.5,end)]:
            metrics.append(dict(city='manila',arm=arm,window=window,**a.p.interval(trace,start,stop)))
        proof,_=a.packet_proof(trace,event);undo=a.undo_checks(trace,arm,event,proof)
        (HERE/(arm+'_packet_evidence.json')).write_text(json.dumps(proof,indent=2)+'\n')
        details.append(dict(arm=arm,**ctrl,undo=undo,event2_unnecessary=sum(x['original_before_trigger'] for x in proof if t<=x['time_s']<t+2)))
        print('ANALYZED',arm,flush=True)
    index={(m['arm'],m['window']):m for m in metrics};detail={d['arm']:d for d in details};new='queue_guard_undo';reasons=[]
    throughput_ref=max(('v5','undo','guard_watch_undo'),key=lambda arm:index[arm,'event10']['ack_mbps'])
    if index[new,'event10']['ack_mbps']<.99*index[throughput_ref,'event10']['ack_mbps']:reasons.append('goodput below 99% of best reference')
    for reference in ('v5','guard_watch_undo'):
        if index[new,'whole']['tc_drops']+detail[new]['gate_drops']>index[reference,'whole']['tc_drops']+detail[reference]['gate_drops']:reasons.append('whole loss greater than '+reference)
        if index[new,'whole']['rtos']>index[reference,'whole']['rtos']:reasons.append('whole RTO greater than '+reference)
    for reference in ('v5','auto_watch_undo'):
        if index[new,'event2']['last_rtt_p95_ms']>1.1*index[reference,'event2']['last_rtt_p95_ms']:reasons.append('RTT >110% of '+reference)
    if index[new,'event10']['retransmissions']:reasons.append('event retransmissions remain')
    if detail[new]['failed']:reasons.append('controller fallback')
    summary=[dict(arm=arm,mbps=index[arm,'event10']['ack_mbps'],retx=index[arm,'event10']['retransmissions'],drops=index[arm,'event10']['tc_drops'],rto=index[arm,'event10']['rtos'],rtt_p95=index[arm,'event2']['last_rtt_p95_ms'],undo_apply=len(detail[arm]['undo']['apply']),max_gate_wait_ms=max(g['max_wait_ms'] for g in detail[arm]['gates']),gate_drops=detail[arm]['gate_drops']) for arm in ARMS]
    result=dict(metrics=metrics,details=details,summary=summary,passed=not reasons,reasons=reasons,plan_sha256=exp.sha(HERE/'frozen_plan.json'))
    (HERE/'results.json').write_text(json.dumps(result,indent=2)+'\n')
    with (HERE/'comparison.csv').open('w',encoding='utf-8-sig',newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=list(summary[0]));writer.writeheader();writer.writerows(summary)
    print(json.dumps(dict(summary=summary,passed=not reasons,reasons=reasons),indent=2),flush=True)

if __name__=='__main__':
    assert sys.argv[1] in ('freeze','generate_worker','generate','run','analyze')
    globals()[sys.argv[1]]()
