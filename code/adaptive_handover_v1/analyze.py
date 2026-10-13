"""Paired evaluation; all thresholds were frozen before these six runs."""
import csv
import importlib.util
import json
from pathlib import Path
import re

HERE=Path(__file__).resolve().parent
ROOT=HERE.parent
spec=importlib.util.spec_from_file_location('timing',ROOT/'route_timing_pilot/analyze.py')
timing=importlib.util.module_from_spec(spec);spec.loader.exec_module(timing)
p=timing.p
LABELS={'baseline':'기본 방식','pace':'페이싱만','auto':'자동 v1'}
CITIES={'newyork':'뉴욕','london':'런던'}

def controller(run,mode,event):
    folder=run['folder'];start=event['start_ns']+1
    rows=p.rows(folder/'handover.csv')
    decisions=[{k:int(v) for k,v in r.items()} for r in p.rows(folder/'decisions.csv')]
    assert all(int(r['time_ns'])>=start for r in rows)
    if mode=='auto':
        assert len(decisions)==2
        for d,g in zip(decisions,event['directions']):
            assert d['time_ns']==event['start_ns']-1 and d['node']==g['node']
            assert bool(d['geometry_allows_retention'])==g['can_retain']
            assert bool(d['retain'])==(g['can_retain'] and d['retained_upper_ns']<=100_000_000)
            expected=d['old_upper_ns']-d['new_lower_ns']+2_000_000 if d['old_upper_ns']>d['new_lower_ns'] else 0
            assert d['gap_ns']==expected
        retain=[r for r in rows if r['event']=='retain'];restore=[r for r in rows if r['event']=='restore']
        assert len(retain)==len(restore)==sum(len(g['changes']) for g,d in zip(event['directions'],decisions) if d['retain'])
        assert all(int(r['time_ns'])==start for r in retain)
        assert all(int(r['time_ns'])==start+100_000_000 for r in restore)
    else:assert not decisions
    caps=[(int(r['time_ns']),float(r['payload_bytes'])) for r in rows if r['event']=='pacing_cap']
    assert caps==([] if mode=='baseline' else [(start,90)]+[(start+200_000_000+i*50_000_000,90+6*i/8) for i in range(1,9)])
    gates=[]
    for match in re.finditer(r'ADAPT_GATE node=(\d+) gap_ns=(\d+) admitted=(\d+) released=(\d+) peak=(\d+) max_wait_ns=(\d+) drops=(\d+)',(folder/'console.log').read_text()):
        g=dict(zip(('node','gap_ns','admitted','released','peak','max_wait_ns','drops'),map(int,match.groups())))
        incoming=[r for r in rows if r['event']=='enqueue' and int(r['node'])==g['node']]
        outgoing=[r for r in rows if r['event']=='release' and int(r['node'])==g['node']]
        assert len(incoming)==len(outgoing)==g['admitted']==g['released']
        assert [(r['seq'],r['ack'],r['scheduled_ns']) for r in incoming]==[(r['seq'],r['ack'],r['time_ns']) for r in outgoing]
        assert g['peak']<=100
        assert sum(r['event']=='buffer_drop' and int(r['node'])==g['node'] for r in rows)==g['drops']
        g['last_release_s']=max((int(r['time_ns'])/1e9 for r in outgoing),default=None)
        gates.append(g)
    assert len(gates)==2
    return dict(decisions=decisions,gates=gates,gate_drops=sum(g['drops'] for g in gates))

def same_prefix(a,b,until):
    for key in ('cwnd','rtt','progress'):
        assert [x for x in a['raw'][key] if x[1]<until]==[x for x in b['raw'][key] if x[1]<until],key
    assert [x for x in a['drops'] if int(x['time_ns'])<until]==[x for x in b['drops'] if int(x['time_ns'])<until]
    assert [x for x in a['retxs'] if x['time_ns']<until]==[x for x in b['retxs'] if x['time_ns']<until]
    assert [(t,v) for t,v in zip(*a['data']['last_rtt']) if t<until]==[(t,v) for t,v in zip(*b['data']['last_rtt']) if t<until]

def ack_reordering(folder,start):
    """Count strictly older cumulative ACKs at the sender, excluding duplicate ACKs."""
    highest=None;count=0;observed=[]
    with (folder/'diagnostic_packets.csv').open(newline='') as f:
        for row in csv.DictReader(f):
            t=int(row['time_ns'])
            if row['event']!='ip_rx' or row['node']!='1584' or not (start-1)*1e9<=t<(start+2)*1e9:continue
            q=p.packet(row)
            if q['payload']:continue
            b=bytes.fromhex(row['hex_prefix']);ih=(b[0]&15)*4
            if not b[ih+13]&16:continue
            ack=int.from_bytes(b[ih+8:ih+12],'big');observed.append(ack)
            if highest is not None and ack<highest and t>=start*1e9:count+=1
            highest=max(highest if highest is not None else ack,ack)
    assert observed and max(observed)-min(observed)<2**31,'ACK wrap requires serial arithmetic'
    return count

def crossing_evidence(run,event):
    x=timing.crossing_packets(run,dict(switch_s=event['switch_s'],event_s=event['switch_s']))
    gate=p.rows(run['folder']/'handover.csv')
    seqs={int(z['seq']) for z in gate if z['event']=='enqueue' and int(z['payload_bytes'])>0}
    x['minimum_enqueued_data_seq']=min(seqs,default=None)
    x['reordered_originals_admitted_to_gate']=[dict(late_seq=v['late']['seq'],earlier_seq=v['earlier_arrival']['seq'],
        late_gated=v['late']['seq'] in seqs,earlier_gated=v['earlier_arrival']['seq'] in seqs) for v in x['reordering_examples']]
    return x

def main():
    plan=json.loads((HERE/'plan.json').read_text())
    index={r['case']:ROOT/r['folder'] for r in json.loads((HERE/'runs.json').read_text())}
    metrics=[];events=[];curves={};checks=[];failure_evidence={}
    for event in plan['events']:
        city=event['city'];start=event['switch_s'];end=event['stop_s'];base=p.load(folder=index[city+'_baseline'])
        old_records=json.loads((ROOT/'route_timing_pilot/runs.json').read_text())
        old=p.load(folder=ROOT/next(r['folder'] for r in old_records if r['case']==city+'_advance0'))
        prior_end=old['data']['progress'][0][-1]
        same_prefix(base,old,prior_end)
        del old
        checks.append(city+': disabled controller reproduces prior baseline through '+str(prior_end/1e9)+' s (excluding termination row)')
        curves[city]={}
        for mode in plan['modes']:
            name=city+'_'+mode;run=base if mode=='baseline' else p.load(folder=index[name])
            same_prefix(run,base,event['start_ns'])
            assert run['data']['progress'][0][-1]==round(end*1e9)
            for window,a,b in [('pre2',start-2,start),('post2',start,start+2),('post5',start,start+5),('through_end',start,end)]:
                metrics.append(dict(case=name,city=city,mode=mode,window=window,**p.interval(run,a,b)))
            evidence,summary=p.packet_evidence(run,[(start-1,start+3.5)],[start])
            ev=dict(case=name,city=city,mode=mode,**summary[0],**controller(run,mode,event),**timing.recovery(run,start))
            ev['post2_older_ack_arrivals']=ack_reordering(run['folder'],start)
            if city=='london' and mode in ('baseline','auto'):failure_evidence[mode]=crossing_evidence(run,event)
            ev['proven_unnecessary']=sum(v for k,v in ev['post2_retransmission_status'].items() if k.endswith('received_before_retransmission'))
            assert ev['post2_retransmissions']==p.interval(run,start,start+2)['retransmissions']
            (HERE/(name+'_packet_evidence.json')).write_text(json.dumps(evidence,indent=2))
            events.append(ev)
            ts=[round((start-1+i*.1)*1e9) for i in range(round((end-start+1)*10)+1)]
            curves[city][mode]=dict(offset_s=[t/1e9-start for t in ts],
                extra_ack_MB=[(p.at(run['data']['progress'],t)-p.at(base['data']['progress'],t))/1e6 for t in ts],
                cwnd=[p.at(run['data']['cwnd'],t)/p.MSS for t in ts],
                rtt=[p.at(run['data']['last_rtt'],t)/1e6 for t in ts])
            print('ANALYZED',name,'post2 retx/unnecessary',ev['post2_retransmissions'],ev['proven_unnecessary'],flush=True)
            if mode!='baseline':del run
        checks.append(city+': all three modes identical before intervention; native q100 unchanged; selected gates drain FIFO')
    data=dict(metrics=metrics,events=events,checks=checks)
    (HERE/'results.json').write_text(json.dumps(data,indent=2))
    (HERE/'london_failure_evidence.json').write_text(json.dumps(failure_evidence,indent=2))
    (HERE/'plot_data.json').write_text(json.dumps(curves))
    with (HERE/'comparison.csv').open('w',encoding='utf-8-sig',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=list(metrics[0]));writer.writeheader();writer.writerows(metrics)
    report(plan,data);plot(curves)
    print('PASS ALL PAIRED V1 CHECKS',flush=True)

def report(plan,data):
    m={(x['case'],x['window']):x for x in data['metrics']};ev={x['case']:x for x in data['events']}
    lines=['경로별 자동 전환 보호 v1 — 새 전환 사건 검증','2026-10-07','',
        '새 규칙을 고정한 뒤 뉴욕 88.9초와 런던 187.4초의 원래 전환 시점에 적용했다.',
        '이 두 사건은 이전 개선안 튜닝 실험에 쓰지 않았으며, 이번 성능 결과를 보고 파라미터를 다시 맞추지 않았다.',
        '각 사건에서 기본 방식 / 페이싱만 / 자동 v1을 새로 실행했다. CUBIC, 단일 흐름, q100, 100Mbps, 동일 시드 123456789.',
        '페이싱 상한은 100×1380/1434=96.234Mbps의 유효 페이로드 용량에서 계산한다. 초기 floor(0.94×용량)=90, 최종 floor(용량)=96Mbps.',
        '전환 +0.25~0.60초에 8단계로 올리고 측정 종료까지 유지한다. 제어 적용은 라우팅 갱신 후 1ns이다.','',
        '자동 판단:',
        '- 새 경로에 필요하지 않은 기존 중계 설정만 최대 100ms 유지 후보로 둔다. 순환/새 경로 간섭 및 10ms 간격 링크 유효성을 검사한다.',
        '- 전환 직전(t−1ns) 큐 점유량을 읽는다. 유지 후보의 배출 추정시간이 100ms를 넘으면 유지하지 않는다.',
        '- 기존 링크 위 패킷이 변경된 중계 표를 따라 우회할 가능성도 포함하여 남은 도착 시간을 추정한다.',
        '- 기존 패킷 도착 추정시간 > 새 경로 최소 도착시간일 때만, 그 차이+2ms를 데이터/ACK 방향별로 적용한다.',
        '- 이미 분기를 통과한 패킷이 우회해서 되돌아온 경우 다시 대기시키지 않도록 전환 직전 TCP 순번/ACK 경계를 기억한다.',
        '- 대기는 0.5초에 걸쳐 줄이며 별도 대기 버퍼는 방향당 최대 100패킷이다. 실제 장치 큐 q100은 변경하지 않는다.','']
    conclusions=['핵심 결과:']
    for event in plan['events']:
        city=event['city'];b=m[city+'_baseline','post5'];a=m[city+'_auto','post5']
        bf=m[city+'_baseline','through_end'];af=m[city+'_auto','through_end'];pf=m[city+'_pace','through_end']
        conclusions.append(f'- {CITIES[city]} 공통 5초: {b["ack_mbps"]:.3f}→{a["ack_mbps"]:.3f}Mbps ({(a["ack_mbps"]/b["ack_mbps"]-1)*100:+.2f}%).')
        conclusions.append(f'  전체 후속 {event["stop_s"]-event["switch_s"]:.1f}초: {bf["ack_mbps"]:.3f}→{af["ack_mbps"]:.3f}Mbps ({(af["ack_mbps"]/bf["ack_mbps"]-1)*100:+.2f}%), 페이싱만 대비 {(af["ack_mbps"]/pf["ack_mbps"]-1)*100:+.2f}%.')
    conclusions += ['- 자동 선택이 실행됐다는 것과 그 선택이 최선이라는 것은 다르다. 기본 대비 이득과 페이싱 단독 대비 추가 이득을 분리해서 판단해야 한다.','']
    conclusions += ['실패 원인 확인:',
        '- 런던의 원본 역전 도착 4건은 모두 전환 전에 송신한 패킷끼리 발생했다. 관련 패킷은 추가 대기 버퍼에 들어가지 않았고, 기본/자동 v1의 도착 시각도 동일했다.',
        '- 따라서 새로 통과하는 패킷만 기다리게 하는 이번 방식은, 이미 이동 중인 기존 패킷들 사이의 순서 역전을 해결하지 못했다.',
        '- 뉴욕도 ACK 역전 5건이 세 조건에서 모두 남았다. 전체 처리량 이득은 페이싱만으로 재현됐고 추가 ACK 대기의 이득은 확인하지 못했다.',
        '- 다음 후보는 링크가 만료되기 전에 전환을 시작하고, 유효한 시간 안에서 기존 패킷이 빠져나갈 수 있도록 전환 시점과 유지 시간을 함께 계산하는 것이다. 아직 구현/검증한 결론은 아니다.','']
    lines[3:3]=conclusions
    for event in plan['events']:
        city=event['city'];lines += [f'{CITIES[city]}: {event["switch_s"]}초 전환, {event["stop_s"]}초까지 관측']
        for d,g in zip(ev[city+'_auto']['decisions'],event['directions']):
            direction='데이터' if d['destination']==1585 else 'ACK'
            lines.append(f'  {direction}: 노드 {d["node"]}, 기존 설정 유지={bool(d["retain"])}, 대기={d["gap_ns"]/1e6:.6f}ms; 기존 도착 추정 {d["old_upper_ns"]/1e6:.6f}ms / 새 경로 최소 {d["new_lower_ns"]/1e6:.6f}ms.')
            if g['changes']:lines.append(f'    유지 후보 링크의 최악 거리 여유 {g["retention_min_margin_m"]:.3f}m (음수면 유효 범위 초과).')
            else:lines.append('    따로 유지할 기존 중계 설정 없음.')
        for window,title in [('post2','직후 2초'),('post5','공통 5초'),('through_end',f'전체 후속 {event["stop_s"]-event["switch_s"]:.1f}초')]:
            b=m[city+'_baseline',window]
            lines += ['',title,'조건 | ACK Mbps | 기본 대비 | RTT 중앙값/p95 ms | TcDrop | 재전송 | RTO']
            for mode,label in LABELS.items():
                x=m[city+'_'+mode,window]
                lines.append(f'{label} | {x["ack_mbps"]:.3f} | {(x["ack_mbps"]/b["ack_mbps"]-1)*100:+.2f}% | {x["last_rtt_median_ms"]:.0f}/{x["last_rtt_p95_ms"]:.0f} | {x["tc_drops"]} | {x["retransmissions"]} | {x["rtos"]}')
        b=m[city+'_baseline','post5'];pace=m[city+'_pace','post5'];auto=m[city+'_auto','post5']
        lines += ['',f'공통 5초 자동 v1 vs 페이싱만: {(auto["ack_mbps"]/pace["ack_mbps"]-1)*100:+.2f}%.']
        for mode in LABELS:
            e=ev[city+'_'+mode]
            lines.append(f'{LABELS[mode]} 직후 2초: 확인된 불필요 재전송 {e["proven_unnecessary"]}, 원본 역전 도착 {e["post2_reordered_original_arrivals"]}, 더 작은 누적 ACK의 역전 도착 {e["post2_older_ack_arrivals"]}; 별도 버퍼 드롭 {e["gate_drops"]}.')
            for g in e['gates']:
                if g['admitted']:lines.append(f'  대기 노드 {g["node"]}: 최대 {g["peak"]}패킷 / {g["max_wait_ns"]/1e6:.3f}ms, 입장·배출 {g["admitted"]}개, 마지막 배출 {g["last_release_s"]:.9f}초.')
        lines.append('')
    lines += ['검증:',*['- '+x for x in data['checks']],'',
        '해석 범위와 남은 과제:',
        '- 이번 새 두 사건에서는 기존 링크가 만료되어 유지 후보가 모두 거절됐다. 실제 유지 동작을 켜는 분기는 이번 두 사건으로 성능 검증한 것이 아니다.',
        '- 링크 유효성/경로는 궤도와 라우팅 표에서 미리 계산하고, 큐는 실행 중 읽는다. 미래 트래픽/재전송 결과는 판단에 쓰지 않는다.',
        '- 큐를 중앙에서 읽을 수 있는 시뮬레이터 제어기다. 실제 네트워크에서는 계측 지연/오차와 정보 전달 비용을 추가 검증해야 한다.',
        '- 도착 시간은 큐 스냅샷 기반 추정이다. 이후 들어오는 트래픽이나 다른 흐름까지 포괄하는 순서 보장 증명은 아니다.',
        '- 런던은 다음 전환 193.8초 이전인 193.4초에 종료했다. 뉴욕 16초와 런던 6초를 같은 길이로 비교하면 안 되며 공통 5초를 함께 봐야 한다.',
        '- 새 도시 전체/다중 흐름/다른 큐 크기/다른 용량/연속 전환의 일반 성능이나 최적성을 입증하지 않았다.',
        '- 페이싱은 경로 용량을 바탕으로 정한 상한이며 혼잡에 따라 상한 자체를 반복 학습하는 제어기는 아니다.',
        '- 현재는 지정된 전환 사건을 입력받아 동작하는 첫 버전이다. 새 사건을 시험할 때 prepare.py의 입력 경로/시점을 추가하고 기하 정보를 생성하며, 제어 규칙은 바꾸지 않는다.',
        '- ACK 처리량과 시간가중 LastRTT 분포다. RTT p95는 패킷별 지연의 p95가 아니며, 전환 이후 손실/RTO만 표에 집계했다.',
        '- TcDrop과 별도 대기 버퍼 드롭을 각각 집계한다. 버퍼를 켠 조건은 총 메모리 자원이 더 많다.',
        '- TCP 손실 판정/CUBIC 및 팀 공유 TcDrop 진단 코드는 유지했다. 변경점과 실행 해시는 simulator.patch와 provenance.json에 있다.','',
        '재현: 컨테이너에서 prepare.py; Windows에서 run.py build → run.py run → analyze.py → run.py restore.',
        '원본 복원과 재빌드 확인: restore_verification.json. 기존 결과를 덮어쓰지 않는 별도 결과 폴더를 사용한다.']
    (HERE/'실험결과.txt').write_text('\n'.join(lines)+'\n',encoding='utf-8-sig')

def plot(curves):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    plt.rcParams.update({'font.family':'Malgun Gothic','axes.unicode_minus':False,'font.size':10})
    fig,axes=plt.subplots(3,2,figsize=(13,10),sharex='col',constrained_layout=True)
    for j,(city,modes) in enumerate(curves.items()):
        for mode,d in modes.items():
            for i,key in enumerate(('extra_ack_MB','cwnd','rtt')):axes[i,j].plot(d['offset_s'],d[key],label=LABELS[mode],linewidth=1.2)
        axes[0,j].set_title(CITIES[city]+' 새 전환 — 자동 v1')
        axes[0,j].legend();axes[2,j].set_xlabel('전환 후 시간 (초)')
        for i,label in enumerate(('기본 대비 추가 ACK (MB)','cwnd (MSS)','최근 RTT (ms)')):
            axes[i,j].set_ylabel(label);axes[i,j].grid(alpha=.2);axes[i,j].axvline(0,color='gray',linestyle=':')
    fig.savefig(HERE/'overview.png',dpi=160);plt.close(fig)

if __name__=='__main__':main()
