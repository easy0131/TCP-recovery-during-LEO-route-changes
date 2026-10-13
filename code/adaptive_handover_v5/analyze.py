"""Paired trace checks and predeclared transfer criteria, without retuning."""
import csv
import importlib.util
import json
from pathlib import Path
import sys
HERE=Path(__file__).resolve().parent
ROOT=HERE.parent
spec=importlib.util.spec_from_file_location('v2analysis',ROOT/'adaptive_handover_v2/analyze.py')
v2=importlib.util.module_from_spec(spec);spec.loader.exec_module(v2)
p,v1,sha=v2.p,v2.v1,v2.sha

def controller(run,mode,event,rate):
    rows=p.rows(run['folder']/'controller.csv');gate_rows=p.rows(run['folder']/'handover.csv')
    get=lambda tag:[r for r in rows if r['event']==tag]
    starts=get('activate');failures=get('no_safe_overlap')+get('memory_fallback');finish=get('finish')
    assert len(finish)==1 and len(starts)+len(failures)==int(mode=='adaptive')
    start=int(starts[0]['time_ns']) if starts else None
    if start is not None:
        assert event['first_check_ns']<=start<=event['nominal_ns']+3
        assert len(get('direction'))==2
        for d,g in zip(get('direction'),event['directions']):
            drain=int(d['value_a']);assert drain>=g['old_prop_ns']+2*event['grid_ns'] and start+drain<=event['safe_end_ns']
            rr=[r for r in get('retire') if int(r['node'])==g['node']]
            assert len(rr)==int(bool(g['keep']))
            if rr:assert int(rr[0]['time_ns'])==start+drain
    caps=get('pacing_bps');specs=get('capacity_bps');rtts=get('rtt_ns');sizes=get('packet_bytes')
    if mode=='baseline':assert not caps and not specs and not gate_rows
    else:
        assert specs and rtts and sizes
        for c,r,s in zip(specs,rtts,sizes):
            assert int(c['value_a'])==rate*1_000_000
            payload,wire=int(s['value_a']),int(s['value_b']);new_rtt=int(r['value_b'])
            expected=max(rate*1e6*payload/wire/2,rate*1e6*payload/wire-payload*8e9/new_rtt)
            assert abs(int(c['value_b'])-expected)<1.01
        assert all(0<int(c['value_a'])<=int(specs[-1]['value_b']) for c in caps)
    gates=[]
    for g in event['directions']:
        node=g['node'];select=lambda tag:[r for r in get(tag) if int(r['node'])==node]
        peak=select('gate_peak');totals=select('gate_totals');wait=select('gate_max_wait');budget=select('buffer_bytes')
        assert len(peak)==len(totals)==len(wait)==1
        incoming=[r for r in gate_rows if int(r['node'])==node and r['event']=='enqueue']
        outgoing=[r for r in gate_rows if int(r['node'])==node and r['event']=='release']
        assert len(incoming)==len(outgoing)==int(totals[0]['value_a'])
        assert [(r['seq'],r['ack'],r['scheduled_ns'],r['payload_bytes']) for r in incoming]==[(r['seq'],r['ack'],r['time_ns'],r['payload_bytes']) for r in outgoing]
        assert [int(r['time_ns']) for r in outgoing]==sorted(int(r['time_ns']) for r in outgoing)
        drops=sum(r['event']=='buffer_drop' and int(r['node'])==node for r in gate_rows)
        assert drops==int(totals[0]['value_b'])
        capacity=int(budget[0]['value_a']) if budget else 0;peak_bytes=int(peak[0]['value_b'])
        assert peak_bytes<=capacity<=4*1024*1024
        assert max((int(r['buffer_bytes']) for r in incoming),default=0)==peak_bytes
        if outgoing:assert int(outgoing[-1]['buffer_bytes'])==0
        gates.append(dict(node=node,capacity_bytes=capacity,peak_bytes=peak_bytes,peak_packets=int(peak[0]['value_a']),
            admitted=len(incoming),drops=drops,max_wait_ms=int(wait[0]['value_a'])/1e6))
    return dict(actual_start_s=start/1e9 if start is not None else None,failed=bool(failures),failure_rows=failures,
        gate_drops=sum(g['drops'] for g in gates),gates=gates,pacing_used=bool(caps),
        first_pacing_mbps=int(caps[0]['value_a'])/1e6 if caps else None,
        safe_pacing_mbps=int(specs[-1]['value_b'])/1e6 if specs else None,
        last_pacing_mbps=int(caps[-1]['value_a'])/1e6 if caps else None,pacing_updates=len(caps),
        measured_rtt_rows=rtts,decision_rows=get('direction'),trigger_rows=get('pacing_trigger'))

def main(stage):
    cities=['sydney'] if stage=='development' else ['singapore','losangeles'];modes=['baseline','adaptive'] if stage=='development' else ['baseline','pace','adaptive']
    metrics=[];events=[];checks=[];comparisons=[];curves={}
    if stage!='development':
        frozen=json.loads((HERE/'frozen_rules.json').read_text());assert sha(HERE/'provenance.json')==frozen['provenance_sha256']
    for city in cities:
        e=json.loads((HERE/(city+'_event.json')).read_text());t=e['nominal_s'];end=e['stop_s'];begin=min(t-.5,e['first_check_ns']/1e9)
        for rate in (50,100,200):
            key=f'{city}_{rate}';base=p.load(folder=ROOT/'runs'/('adaptive_v5_q100_'+key+'_baseline'))
            if city=='sydney' and rate==100:
                old=p.load(folder=ROOT/'runs/adaptive_v3_q100_sydney_baseline');v1.same_prefix(base,old,round(end*1e9));del old
                checks.append('Sydney 100Mbps disabled v5 exactly reproduces prior baseline transport traces, excluding termination row.')
            curves[key]={}
            for mode in modes:
                name=key+'_'+mode;run=base if mode=='baseline' else p.load(folder=ROOT/'runs'/('adaptive_v5_q100_'+name))
                for f in ('config_ns3.properties','schedule.csv'):assert (run['folder']/f).read_bytes()==(base['folder']/f).read_bytes()
                manifest=json.loads((run['folder']/'manifest.json').read_text())
                assert manifest['event_sha256']==sha(HERE/(city+'_event.txt'))
                v1.same_prefix(run,base,e['first_check_ns']);c=controller(run,mode,e,rate)
                intervention=round(c['actual_start_s']*1e9) if c['actual_start_s'] is not None else e['nominal_ns']
                if not c['failed']:v1.same_prefix(run,base,intervention)
                assert run['data']['progress'][0][-1]==round(end*1e9)
                for window,a,b in [('short',begin,t+5),('full',begin,end),('post2',t,t+2)]:
                    metrics.append(dict(case=name,city=city,rate_mbps=rate,mode=mode,window=window,**p.interval(run,a,b)))
                proof,summary=v2.packet_proof(run,e)
                events.append(dict(case=name,city=city,rate_mbps=rate,mode=mode,**c,**summary,
                    proven_unnecessary=sum(x['proven_unnecessary_at_tcp_trigger'] for x in proof),proof_window_s=[t-1,t+3.5]))
                (HERE/(name+'_packet_evidence.json')).write_text(json.dumps(proof,indent=2))
                ns=[round((begin+i*.1)*1e9) for i in range(round((end-begin)*10)+1)]
                curves[key][mode]=dict(offset_s=[n/1e9-t for n in ns],extra_ack_MB=[(p.at(run['data']['progress'],n)-p.at(base['data']['progress'],n))/1e6 for n in ns],
                    cwnd=[p.at(run['data']['cwnd'],n)/p.MSS for n in ns],rtt=[p.at(run['data']['last_rtt'],n)/1e6 for n in ns])
                print('ANALYZED',name,'gate drops',c['gate_drops'],'safe cap',c['safe_pacing_mbps'],flush=True)
                if mode!='baseline':del run
            checks.append(key+': paired inputs/pre-intervention traces, unchanged q100, TcDrop/RTO coverage, FIFO bytes and geometry deadlines checked.')
            m={(r['case'],r['window']):r for r in metrics};ev={r['case']:r for r in events}
            for mode in modes[1:]:
                name=key+'_'+mode;b=m[key+'_baseline','full'];a=m[name,'full'];c=ev[name]
                short=m[name,'short']['ack_mbps']/m[key+'_baseline','short']['ack_mbps'];full=a['ack_mbps']/b['ack_mbps']
                brtt=m[key+'_baseline','post2']['last_rtt_p95_ms'];artt=m[name,'post2']['last_rtt_p95_ms']
                reasons=[]
                if min(short,full)<.99:reasons.append('goodput below 99% of baseline')
                if a['rtos']>b['rtos']:reasons.append('additional RTO')
                if a['tc_drops']+c['gate_drops']>b['tc_drops']:reasons.append('additional drops')
                if artt>brtt*1.10:reasons.append('post2 RTT p95 increased over 10%')
                if c['gate_drops']:reasons.append('gate overflow')
                comparisons.append(dict(city=city,rate_mbps=rate,mode=mode,short_gain_pct=(short-1)*100,full_gain_pct=(full-1)*100,
                    baseline_short_mbps=m[key+'_baseline','short']['ack_mbps'],short_mbps=m[name,'short']['ack_mbps'],
                    baseline_full_mbps=b['ack_mbps'],full_mbps=a['ack_mbps'],baseline_rtt_p95_ms=brtt,rtt_p95_ms=artt,
                    baseline_tc_drops=b['tc_drops'],tc_drops=a['tc_drops'],gate_drops=c['gate_drops'],
                    baseline_retx=b['retransmissions'],retx=a['retransmissions'],baseline_rto=b['rtos'],rto=a['rtos'],
                    passed=not reasons,reasons=reasons,fallback=c['failed'],peak_extra_bytes=sum(g['peak_bytes'] for g in c['gates'])))
    data=dict(stage=stage,metrics=metrics,events=events,comparisons=comparisons,checks=checks,provenance_sha256=sha(HERE/'provenance.json'))
    (HERE/(stage+'_results.json')).write_text(json.dumps(data,indent=2));(HERE/(stage+'_plot_data.json')).write_text(json.dumps(curves))
    with (HERE/(stage+'_comparison.csv')).open('w',encoding='utf-8-sig',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(comparisons[0]));w.writeheader();w.writerows(comparisons)
    print(json.dumps(comparisons,ensure_ascii=False,indent=2),flush=True)
    print('PASS trace validation; performance verdicts above may fail',flush=True)

if __name__=='__main__':main(sys.argv[1])
