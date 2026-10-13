"""Reuse existing paired-trace and packet-identity checks for the frozen ablation."""
import csv
import importlib.util
import json
from pathlib import Path
import re
import sys

HERE=Path(__file__).resolve().parent
ROOT=HERE.parent
spec=importlib.util.spec_from_file_location('hybrid_v5_analysis',ROOT/'adaptive_handover_v5/analyze.py')
v5=importlib.util.module_from_spec(spec);spec.loader.exec_module(v5)
p,sha=v5.p,v5.sha

def records(text,tag):
    return [dict(re.findall(r'(\w+)=([^\s]+)',line)) for line in text.splitlines() if line.startswith(tag+' ')]

def packet_proof(run,event):
    shifts={(int(r['time_ns']),int(r['seq']),int(r['payload_bytes'])):int(r['scheduled_ns'])
        for r in p.rows(run['folder']/'handover.csv') if r['event']=='enqueue' and r['node']=='1584' and int(r['payload_bytes'])>0}
    wire=[];triggers={}
    for r in run['retxs']:
        t=shifts.get((r['time_ns'],r['seq'],r['payload_bytes']),r['time_ns'])
        wire.append(dict(r,time_ns=t));triggers[t,r['seq']]=r['time_ns']
    t=event['nominal_s']
    evidence,summaries=p.packet_evidence(dict(run,retxs=wire),[(t-2.2,t+6)],[t])
    for e in evidence:
        trigger=triggers[round(e['time_s']*1e9),e['seq']]
        e['wire_time_s']=e['time_s'];e['time_s']=trigger/1e9
        e['original_before_trigger']=e['original_rx_s'] is not None and round(e['original_rx_s']*1e9)<trigger
    targets={e['seq'] for e in evidence}
    dropped={p.packet(r)['identity']:int(r['time_ns']) for r in run['drops'] if r['event']=='TcDrop' and r['tcp_decoded']=='1' and int(r['seq']) in targets}
    retx_keys={(r['time_ns'],r['seq']) for r in wire};original_drops={}
    if dropped:
        with (run['folder']/'diagnostic_packets.csv').open(newline='') as stream:
            for row in csv.DictReader(stream):
                if row['event']!='ip_tx' or row['node']!='1584' or not (t-2.2)*1e9<=int(row['time_ns'])<=(t+6)*1e9:continue
                packet=p.packet(row)
                if packet['identity'] in dropped and (packet['time_ns'],packet['seq']) not in retx_keys:
                    original_drops[packet['seq']]=dropped[packet['identity']]/1e9
    for e in evidence:
        e['original_drop_s']=original_drops.get(e['seq'])
        assert e['original_drop_s'] is None or e['original_rx_s'] is None
    return evidence,summaries[0]

def undo_checks(run,arm,event,proof):
    text=(run['folder']/'console.log').read_text()
    names=['ARM','BEGIN','APPLY','REJECT']
    logs={tag.lower():records(text,'LAB1_UNDO_'+tag) for tag in names}
    logs.update(skips=records(text,'HYBRID_UNDO_SKIP'),components=records(text,'HYBRID_UNDO_COMPONENT'),
        evidence=records(text,'HYBRID_UNDO_EVIDENCE'),windows=records(text,'HYBRID_UNDO_WINDOW'))
    enabled=arm not in ('baseline','v5')
    assert len(logs['arm'])==len(logs['windows'])==int(enabled)
    assert len(logs['begin'])<=1 and len(logs['apply'])+len(logs['reject'])==len(logs['begin'])
    if enabled:assert int(logs['arm'][0]['time_ns'])==event['nominal_ns']
    for r,c in zip(logs['apply'],logs['components']):
        assert int(r['proven'])==int(r['retransmissions'])>0
        assert int(c['full'])==int(arm=='undo_full')
        if arm!='undo_full':assert c['cwnd_before']==c['cwnd_after']
        start=int(logs['begin'][0]['time_ns']);end=int(r['time_ns'])
        actual=[x for x in proof if start<=round(x['time_s']*1e9)<=end]
        assert len(actual)==int(r['retransmissions'])
        assert all(x['original_rx_s'] is not None for x in actual),'Undo applied to a non-delivered original'
    assert len(logs['components'])==len(logs['apply'])
    recovery=[int(r['time_ns']) for r in run['states'] if r['new_state']=='3' and
        event['first_check_ns']<=int(r['time_ns'])<event['nominal_ns']+6_000_000_000]
    logs['recovery_start_s']=[n/1e9 for n in recovery]
    logs['recoveries_before_arm']=sum(n<event['nominal_ns'] for n in recovery) if enabled else 0
    return logs

def main(stage):
    plan=json.loads((HERE/'frozen_plan.json').read_text())
    cities=plan['heldout'] if stage=='heldout' else plan['development']
    arms=['baseline','undo_full'] if stage=='reproduction' else (['baseline','v5','undo','auto_undo'] if stage=='heldout' else plan['modes'])
    metrics=[];details=[];checks=[];curves={}
    for city in cities:
        event=json.loads((HERE/f'{city}_event.json').read_text());t=event['nominal_s'];end=event['stop_s']
        base=p.load(folder=HERE/'runs'/f'{city}_baseline');curves[city]={}
        for arm in arms:
            name=f'{city}_{arm}';folder=HERE/'runs'/name
            run=base if arm=='baseline' else p.load(folder=folder)
            manifest=json.loads((folder/'manifest.json').read_text())
            assert manifest['exit_code']==0 and manifest['build']==plan['build']
            assert manifest['event_sha256']==sha(HERE/f'{city}_event.txt')==plan['events'][city]
            for f,key in [('config_ns3.properties','config_sha256'),('schedule.csv','schedule_sha256')]:
                assert sha(folder/f)==manifest[key]
                assert (folder/f).read_bytes()==(base['folder']/f).read_bytes()
            assert run['data']['progress'][0][-1]==round(end*1e9)
            v5.v1.same_prefix(run,base,event['first_check_ns'])
            mode='baseline' if arm in ('baseline','undo','undo_full') else 'adaptive'
            control=v5.controller(run,mode,event,100)
            intervention=round(control['actual_start_s']*1e9) if control['actual_start_s'] is not None else event['nominal_ns']
            v5.v1.same_prefix(run,base,intervention)
            if stage=='heldout' and arm in ('baseline','v5'):
                original=ROOT/'runs'/f'adaptive_v5_q100_{city}_100_{"baseline" if arm=="baseline" else "adaptive"}'
                prior=p.load(folder=original)
                v5.v1.same_prefix(run,prior,round(end*1e9));del prior
            for window,a,b in [('pre2',t-2,t),('event2',t,t+2),('event10',t,end),('aligned',t-.5,end),('whole',0,end)]:
                metrics.append(dict(case=name,city=city,arm=arm,window=window,**p.interval(run,a,b)))
            proof,packet_summary=packet_proof(run,event)
            undo=undo_checks(run,arm,event,proof)
            if arm in ('undo','undo_full'):
                until=int(undo['apply'][0]['time_ns']) if undo['apply'] else round(end*1e9)
                v5.v1.same_prefix(run,base,until)
            if arm=='full_undo' and not undo['apply']:
                plain_v5=p.load(folder=HERE/'runs'/f'{city}_v5')
                v5.v1.same_prefix(run,plain_v5,round(end*1e9));del plain_v5
            risks=[r for r in p.rows(folder/'controller.csv') if r['event'] in ('risk_bytes','risk_pacing')]
            if arm=='auto_undo':
                assert len(risks)==2
                assert (int(risks[0]['value_a'])>int(risks[0]['value_b']))==bool(int(risks[1]['value_a']))==control['pacing_used']
            else:assert not risks
            selected=[x for x in proof if t<=x['time_s']<t+2]
            details.append(dict(case=name,city=city,arm=arm,**control,**packet_summary,undo=undo,risk=risks,
                proof_window_s=[t-2.2,t+6],event2_original_received=sum(x['original_before_trigger'] for x in selected),
                event2_original_eventually_received=sum(x['original_rx_s'] is not None for x in selected),
                event2_original_drop_proven=sum(x['original_drop_s'] is not None for x in selected),
                event2_original_delivery_unproven=sum(x['original_rx_s'] is None for x in selected)))
            (HERE/f'{name}_packet_evidence.json').write_text(json.dumps(proof,indent=2)+'\n')
            ns=[round((t-.5+i*.05)*1e9) for i in range(round((end-t+.5)*20)+1)]
            curves[city][arm]=dict(offset_s=[n/1e9-t for n in ns],
                extra_ack_MB=[(p.at(run['data']['progress'],n)-p.at(base['data']['progress'],n))/1e6 for n in ns],
                cwnd=[p.at(run['data']['cwnd'],n)/p.MSS for n in ns],rtt=[p.at(run['data']['last_rtt'],n)/1e6 for n in ns])
            m=next(x for x in metrics if x['case']==name and x['window']=='event10')
            print('ANALYZED',name,'Mbps',round(m['ack_mbps'],6),'drops',m['tc_drops'],'undo',len(undo['apply']),flush=True)
            if arm!='baseline':del run
        checks.append(city+': paired inputs, frozen code, identical pre-intervention transport, queue size/coverage, RTO evidence, drain deadlines, gate FIFO and original-packet identity checked.')
    index={(r['city'],r['arm'],r['window']):r for r in metrics}
    if stage=='reproduction':
        expected={('london','baseline'):(63.51864,68.956944,0,28),('london','undo_full'):(85.90776,93.925008,0,28),
            ('newyork','baseline'):(82.94904,90.564432,18,55),('newyork','undo_full'):(82.94904,90.564432,18,55)}
        for (city,arm),(rate2,rate10,drops,retx) in expected.items():
            a=index[city,arm,'event2'];b=index[city,arm,'event10']
            assert abs(a['ack_mbps']-rate2)<1e-6 and abs(b['ack_mbps']-rate10)<1e-6,(city,arm,a,b)
            assert (a['tc_drops'],a['retransmissions'])==(drops,retx)
        checks.append('Original full undo and both baselines reproduce reference event2/event10 rates, drops and retransmissions exactly to 1e-6 Mbps.')
    comparisons=[]
    if stage!='reproduction':
        for city in cities:
            best=max(('v5','undo'),key=lambda a:index[city,a,'event10']['ack_mbps'])
            a=index[city,'auto_undo','event10'];b=index[city,best,'event10'];v=index[city,'v5','event10']
            ar=index[city,'auto_undo','event2']['last_rtt_p95_ms'];br=index[city,best,'event2']['last_rtt_p95_ms']
            reasons=[]
            if a['ack_mbps']<.99*b['ack_mbps']:reasons.append('event10 goodput below 99% of better v5/undo')
            # Include proactive action before nominal and startup losses, not just post-switch losses.
            if index[city,'auto_undo','whole']['tc_drops']>index[city,'v5','whole']['tc_drops']:reasons.append('additional whole-run drops vs v5')
            if index[city,'auto_undo','whole']['rtos']>index[city,'v5','whole']['rtos']:reasons.append('additional whole-run RTO vs v5')
            if ar>1.1*br:reasons.append('event2 RTT p95 exceeds 110% of better-throughput arm')
            comparisons.append(dict(city=city,reference=best,auto_mbps=a['ack_mbps'],reference_mbps=b['ack_mbps'],
                difference_pct=(a['ack_mbps']/b['ack_mbps']-1)*100,passed=not reasons,reasons=reasons))
    result=dict(stage=stage,plan_sha256=sha(HERE/'frozen_plan.json'),metrics=metrics,details=details,checks=checks,comparisons=comparisons)
    (HERE/f'{stage}_results.json').write_text(json.dumps(result,indent=2)+'\n')
    (HERE/f'{stage}_curves.json').write_text(json.dumps(curves)+'\n')
    with (HERE/f'{stage}_metrics.csv').open('w',encoding='utf-8-sig',newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=list(metrics[0]));writer.writeheader();writer.writerows(metrics)
    print('PASS TRACE VALIDATION',stage,flush=True)
    print(json.dumps(comparisons,indent=2),flush=True)

if __name__=='__main__':
    assert records('LAB1_UNDO_APPLY time_ns=10 proven=2 retransmissions=2','LAB1_UNDO_APPLY')==[{'time_ns':'10','proven':'2','retransmissions':'2'}]
    assert sys.argv[1] in ('reproduction','development','heldout')
    main(sys.argv[1])
