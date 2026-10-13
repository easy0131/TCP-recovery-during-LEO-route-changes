"""Freeze a rule on three known events, then evaluate untouched Sydney outcomes."""
import csv
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import re
import sys
HERE=Path(__file__).resolve().parent
ROOT=HERE.parent
spec=importlib.util.spec_from_file_location('v1_analysis',ROOT/'adaptive_handover_v1/analyze.py')
v1=importlib.util.module_from_spec(spec);spec.loader.exec_module(v1)
p,timing=v1.p,v1.timing
LABELS=dict(baseline='기본 방식',pace='기존 페이싱만',early='조기 전환 + 페이싱',drain='조기 전환 + 배출 보호 + 페이싱',
    guard='조기 전환 + 배출 보호 + 선택적 대기 + 페이싱',unpaced='조기 전환 + 배출 보호 + 선택적 대기')
NAMES=dict(newyork48='뉴욕 48.9초',newyork='뉴욕 88.9초',london='런던 187.4초',sydney='시드니 26.2초')
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def controller(run,mode,event,expected_caps=None,gate_limits=None):
    rows=p.rows(run['folder']/'controller.csv');gate_rows=p.rows(run['folder']/'handover.csv')
    starts=[r for r in rows if r['event']=='activate'];failed=[r for r in rows if r['event']=='no_safe_overlap']
    start=int(starts[0]['time_ns']) if starts else None
    active=mode not in ('baseline','pace')
    assert len(starts)+len(failed)==int(active)
    directions=[r for r in rows if r['event']=='direction'];retired=[r for r in rows if r['event']=='retire']
    caps=[(int(r['time_ns']),float(r['value_a'])) for r in rows if r['event']=='pacing_cap']
    if start is not None:
        assert event['first_check_ns']<=start<=event['nominal_ns']+3
        assert len(directions)==2
        for d,g in zip(directions,event['directions']):
            drain=int(d['value_a']);assert int(d['node'])==g['node']
            assert drain>=g['old_base_ns']+2_000_000 and start+drain<=event['safe_end_ns']
            rr=[r for r in retired if int(r['node'])==g['node']]
            assert len(rr)==int(bool(g['keep']) and mode!='early')
            if rr:assert int(rr[0]['time_ns'])==start+drain
        expected_cap=max(90,math.floor((100*1380/1434)*min(1,event['new_rtt_ns']/event['old_rtt_ns'])))
        expected=[] if mode=='unpaced' else [(start,expected_cap)]+[(start+200_000_000+i*50_000_000,expected_cap+(96-expected_cap)*i/8) for i in range(1,9)]
        if expected_caps is not None:expected=expected_caps
        assert caps==expected,(mode,caps,expected)
    elif mode=='pace':
        nominal=event['nominal_ns']+3
        assert caps==[(nominal,90)]+[(nominal+200_000_000+i*50_000_000,90+6*i/8) for i in range(1,9)]
    else:assert not caps
    gates=[]
    for match in re.finditer(r'ADAPT_GATE node=(\d+) gap_ns=(\d+) admitted=(\d+) released=(\d+) peak=(\d+) max_wait_ns=(\d+) drops=(\d+)',(run['folder']/'console.log').read_text()):
        g=dict(zip(('node','gap_ns','admitted','released','peak','max_wait_ns','drops'),map(int,match.groups())))
        incoming=[r for r in gate_rows if r['event']=='enqueue' and int(r['node'])==g['node']]
        outgoing=[r for r in gate_rows if r['event']=='release' and int(r['node'])==g['node']]
        assert len(incoming)==len(outgoing)==g['admitted']==g['released'] and g['peak']<=(gate_limits or {}).get(g['node'],100)
        assert [(r['seq'],r['ack'],r['scheduled_ns']) for r in incoming]==[(r['seq'],r['ack'],r['time_ns']) for r in outgoing]
        assert g['drops']==sum(r['event']=='buffer_drop' and int(r['node'])==g['node'] for r in gate_rows)
        g['last_release_s']=max((int(r['time_ns'])/1e9 for r in outgoing),default=None)
        gates.append(g)
    assert len(gates)==2
    return dict(actual_start_s=start/1e9 if start is not None else None,failed=bool(failed),directions=directions,
        retired=retired,gates=gates,gate_drops=sum(g['drops'] for g in gates),initial_pacing_mbps=caps[0][1] if caps else None)

def packet_proof(run,event):
    # When a gate is on the sender, IP Tx occurs after TCP's retransmission callback.
    shifts={(int(r['time_ns']),int(r['seq']),int(r['payload_bytes'])):int(r['scheduled_ns'])
        for r in p.rows(run['folder']/'handover.csv') if r['event']=='enqueue' and r['node']=='1584' and int(r['payload_bytes'])>0}
    wire=[];triggers={}
    for r in run['retxs']:
        t=shifts.get((r['time_ns'],r['seq'],r['payload_bytes']),r['time_ns'])
        wire.append(dict(r,time_ns=t));triggers[t,r['seq']]=r['time_ns']
    adapted=dict(run,retxs=wire)
    t=event['nominal_s'];evidence,summaries=p.packet_evidence(adapted,[(t-1,t+3.5)],[t])
    for e in evidence:
        ns=round(e['time_s']*1e9);trigger=triggers[ns,e['seq']]
        e['wire_time_s']=e['time_s'];e['time_s']=trigger/1e9
        e['proven_unnecessary_at_tcp_trigger']=e['original_rx_s'] is not None and round(e['original_rx_s']*1e9)<trigger
    return evidence,summaries[0]

def evaluate(stage):
    plan=json.loads((HERE/'plan.json').read_text());index={r['case']:ROOT/r['folder'] for r in json.loads((HERE/'runs.json').read_text())}
    metrics=[];events=[];curves={};checks=[]
    selected=plan['training_cities'] if stage=='train' else ['sydney']
    chosen=json.loads((HERE/'selection.json').read_text())['chosen'] if stage=='heldout' else None
    for city in selected:
        event=next(e for e in plan['events'] if e['city']==city);t=event['nominal_s'];end=event['stop_s']
        base=p.load(folder=index[city+'_baseline']);modes=plan['modes'] if stage=='train' else ['baseline','pace',chosen]
        if city!='sydney':
            reference=ROOT/'runs'/('ny_transition_q100_baseline' if city=='newyork48' else 'adaptive_v1_q100_'+city+'_baseline')
            old=p.load(folder=reference);v1.same_prefix(base,old,round(end*1e9));del old
            checks.append(city+': new disabled binary exactly reproduces prior baseline, excluding termination row')
        curves[city]={}
        for mode in modes:
            name=city+'_'+mode;run=base if mode=='baseline' else p.load(folder=index[name])
            v1.same_prefix(run,base,event['first_check_ns'])
            assert run['data']['progress'][0][-1]==round(end*1e9)
            for window,a,b in [('pre',t-1,t-.5),('aligned5',t-.5,t+5),('post2',t,t+2),('post5',t,t+5),('aligned_end',t-.5,end),('post_end',t,end)]:
                metrics.append(dict(case=name,city=city,mode=mode,window=window,**p.interval(run,a,b)))
            c=controller(run,mode,event);proof,summary=packet_proof(run,event)
            if c['actual_start_s'] is not None:
                v1.same_prefix(run,base,round(c['actual_start_s']*1e9))
            e=dict(case=name,city=city,mode=mode,**c,**summary,
                proven_unnecessary=sum(x['proven_unnecessary_at_tcp_trigger'] for x in proof),
                proof_window_s=[t-1,t+3.5],**timing.recovery(run,c['actual_start_s'] or t))
            events.append(e);(HERE/(name+'_packet_evidence.json')).write_text(json.dumps(proof,indent=2))
            ns=[round((t-1+i*.1)*1e9) for i in range(round((end-t+1)*10)+1)]
            curves[city][mode]=dict(offset_s=[n/1e9-t for n in ns],extra_ack_MB=[(p.at(run['data']['progress'],n)-p.at(base['data']['progress'],n))/1e6 for n in ns],
                cwnd=[p.at(run['data']['cwnd'],n)/p.MSS for n in ns],rtt=[p.at(run['data']['last_rtt'],n)/1e6 for n in ns])
            print('ANALYZED',name,'start',e['actual_start_s'],'unnecessary',e['proven_unnecessary'],'gate drops',e['gate_drops'],flush=True)
            if mode!='baseline':del run
        checks.append(city+': identical before actual intervention; all forecast deadlines respected; all admitted gate packets released FIFO; q100 unchanged')
    data=dict(metrics=metrics,events=events,checks=checks,plan_sha256=sha(HERE/'plan.json'),stage=stage)
    (HERE/(stage+'_results.json')).write_text(json.dumps(data,indent=2))
    (HERE/(stage+'_plot_data.json')).write_text(json.dumps(curves))
    with (HERE/(stage+'_comparison.csv')).open('w',encoding='utf-8-sig',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=list(metrics[0]));writer.writeheader();writer.writerows(metrics)
    if stage=='train':select(plan,data)
    else:report(plan);plot(plan)
    print('PASS',stage,'paired evaluation',flush=True)

def select(plan,data):
    m={(x['case'],x['window']):x for x in data['metrics']};events={x['case']:x for x in data['events']};rank=[]
    for mode in ('guard','drain','unpaced'):
        ratios=[];eligible=True;reasons=[]
        for city in plan['training_cities']:
            c=m[city+'_'+mode,'aligned_end'];b=m[city+'_baseline','aligned_end'];e=events[city+'_'+mode]
            ok=not e['failed'] and c['rtos']<=b['rtos'] and c['tc_drops']+e['gate_drops']<=b['tc_drops']
            eligible &= ok
            if not ok:reasons.append(city+': failed overlap or additional RTO/drop')
            for window in ('aligned5','aligned_end'):ratios.append(m[city+'_'+mode,window]['ack_mbps']/m[city+'_baseline',window]['ack_mbps'])
        rank.append(dict(mode=mode,eligible=eligible,reasons=reasons,minimum_ratio=min(ratios),geometric_mean=math.prod(ratios)**(1/len(ratios)),ratios=ratios))
    eligible=[r for r in rank if r['eligible']]
    assert eligible,'No candidate satisfies constraints; inspect and revise before claiming a winner'
    best=max(eligible,key=lambda r:(r['minimum_ratio'],r['geometric_mean'],{'guard':2,'drain':1,'unpaced':0}[r['mode']]))
    selection=dict(chosen=best['mode'],ranking=rank,training_results_sha256=sha(HERE/'train_results.json'),
        plan_sha256=sha(HERE/'plan.json'),rule=plan['selection'],sydney_outcomes_seen=False)
    dest=HERE/'selection.json'
    if dest.exists():assert json.loads(dest.read_text())==selection,'Do not replace a frozen selection'
    else:dest.write_text(json.dumps(selection,indent=2))
    print('FROZEN SELECTION',json.dumps(selection),flush=True)

def report(plan):
    train=json.loads((HERE/'train_results.json').read_text());test=json.loads((HERE/'heldout_results.json').read_text())
    choice=json.loads((HERE/'selection.json').read_text());chosen=choice['chosen']
    assert choice['training_results_sha256']==sha(HERE/'train_results.json')
    data=dict(metrics=train['metrics']+test['metrics'],events=train['events']+test['events'],checks=train['checks']+test['checks'])
    (HERE/'results.json').write_text(json.dumps(data,indent=2))
    m={(x['case'],x['window']):x for x in data['metrics']};ev={x['case']:x for x in data['events']}
    lines=['예측 기반 경로 전환 v2 — 서울–시드니 별도 검증','2026-10-07','',
        '선택한 후보: '+LABELS[chosen],
        '런던 187.4초 / 뉴욕 48.9초 / 뉴욕 88.9초에서 후보를 비교한 뒤 선택을 고정하고 시드니 26.2초에 적용했다.',
        '전환 관련 TcDrop과 RTO가 기본보다 늘지 않는 후보 중, 세 사건·두 관측 구간의 최저 처리량 비율을 우선하고 기하평균으로 동률을 구분했다.',
        '관측 구간은 원래 전환 시점 0.5초 전부터 +5초까지(5.5초) 및 각 실행 종료까지다. 앞당긴 전환의 비용도 포함했다.',
        '이 유한한 후보·조건에서의 선택이며 보편적 최적해를 증명하지 않았다. RTT와 버퍼 비용은 별도로 함께 제시한다.','',
        '핵심 비교 — 공통 5.5초 창:',
        '사건 | 기본 Mbps | 선택안 Mbps | 변화 | 최근 RTT p95 기본→선택 ms | TcDrop 기본→선택 | 재전송 기본→선택 | RTO 기본→선택']
    for e in plan['events']:
        city=e['city'];b=m[city+'_baseline','aligned5'];a=m[city+'_'+chosen,'aligned5']
        lines.append(f'{NAMES[city]} | {b["ack_mbps"]:.3f} | {a["ack_mbps"]:.3f} | {(a["ack_mbps"]/b["ack_mbps"]-1)*100:+.2f}% | {b["last_rtt_p95_ms"]:.0f}→{a["last_rtt_p95_ms"]:.0f} | {b["tc_drops"]}→{a["tc_drops"]} | {b["retransmissions"]}→{a["retransmissions"]} | {b["rtos"]}→{a["rtos"]}')
    lines+=['','알고리즘:',
        '- 원래 전환 시점 이전 최대 0.5초의 새 경로 가용성과 기존 링크 만료 시각을 궤도에서 예측한다. 기하는 1ms 간격, 만료 여유는 2ms이다.',
        '- 매 1ms 현재 큐를 읽어 기존 패킷 배출 시간(전파+직렬화+큐+2ms)을 추정한다. 마감에 가까워지면 새 경로를 적용하며, 원래 시점보다 늦게 전환하지 않는다.',
        '- 기존 패킷에 필요한 중계 설정은 유효한 시간 안에서만 유지하고, 방향별 배출 시간이 지나면 정리한다.',
        '- 선택적 대기는 기존 경로의 마지막 패킷이 새 패킷보다 늦을 것으로 추정되는 방향에만 켠다. 최대 100패킷, 0.5초에 걸쳐 대기를 줄인다.',
        '- 초기 페이싱 상한은 새/기존 RTT 비율에 따라 90~96Mbps로 계산하고 +0.25~0.60초에 96Mbps로 올린다. CUBIC 자체의 속도 제한도 계속 적용된다.',
        '- 새 경로 가용 시각에 이미 배출 여유가 부족하면 무리하게 옛 링크를 유지하지 않고 기본 라우팅으로 돌아가며 실패를 기록한다.','']
    for e in plan['events']:
        city=e['city'];modes=plan['modes'] if city!='sydney' else ['baseline','pace',chosen]
        lines += [NAMES[city]+f' — 원래 전환 {e["nominal_s"]}초, 종료 {e["stop_s"]}초',
            f'새 경로 사용 가능 {e["new_valid_from_ns"]/1e9:.3f}초, 기존 링크 유지 마감 {e["safe_end_ns"]/1e9:.3f}초.',
            '조건 | 실제 전환 | 5.5초 Mbps | 전체 Mbps | 전체 RTT p95 | 전체 TcDrop/재전송/RTO | 대기 버퍼 드롭 | 확인된 불필요 재전송']
        for mode in modes:
            key=city+'_'+mode;s=ev[key];a=m[key,'aligned5'];f=m[key,'aligned_end']
            when=s['actual_start_s'] if s['actual_start_s'] is not None else e['nominal_s']
            lines.append(f'{LABELS[mode]} | {when:.6f} | {a["ack_mbps"]:.3f} | {f["ack_mbps"]:.3f} | {f["last_rtt_p95_ms"]:.0f} | {f["tc_drops"]}/{f["retransmissions"]}/{f["rtos"]} | {s["gate_drops"]} | {s["proven_unnecessary"]}')
        selected=ev[city+'_'+chosen]
        b2=m[city+'_baseline','post2'];a2=m[city+'_'+chosen,'post2']
        lines.append(f'원래 전환 이후 2초의 RTT p95: {b2["last_rtt_p95_ms"]:.0f}→{a2["last_rtt_p95_ms"]:.0f}ms. 공통 5.5초 창의 전환 전 RTT가 지연 비용을 가리지 않도록 따로 제시한다.')
        lines.append(f'선택안 초기 페이싱 상한: {selected["initial_pacing_mbps"]}Mbps (None은 페이싱 미사용).')
        for d,g in zip(selected['directions'],e['directions']):
            lines.append(f'  {"데이터" if g["destination"]==1585 else "ACK"}: 배출 추정 {int(d["value_a"])/1e6:.3f}ms, 추가 대기 {int(d["value_b"])/1e6:.3f}ms, 유지 후보 {len(g["keep"])}개.')
        for g in selected['gates']:
            if g['admitted']:lines.append(f'  노드 {g["node"]} 대기 버퍼 최대 {g["peak"]}패킷, 최대 대기 {g["max_wait_ns"]/1e6:.3f}ms, 입장·배출 {g["admitted"]}개, 마지막 배출 {g["last_release_s"]:.6f}초.')
        lines.append('')
    lines+=['선택 점수:',json.dumps(choice['ranking'],ensure_ascii=False,indent=2),'',
        '검증:',*['- '+c for c in data['checks']],'',
        '범위와 한계:',
        '- CUBIC, 링크 100Mbps, q100, MSS 1380바이트, 단일 100GB 흐름, 동일 시드 123456789. 다른 부하/큐/용량이나 다중 흐름 공정성은 검증하지 않았다.',
        '- 시드니 좌표는 실습 생성기 형식의 서울(37.56826,126.97783)·시드니(-33.87,151.21)이다. 위성 1584개, 100ms 라우팅 표, 200초를 새로 생성했다.',
        '- 시드니는 처음 60초의 라우팅만 사건 선택과 입력 해시에 사용했다. 첫 번째 고립된 비초기 전환 26.2초를 선택했으며, 다음 전환 54.4초 전인 36.2초에 종료했다.',
        '- 궤도/미리 알려진 경로와 중앙에서 읽는 큐 상태를 사용한 시뮬레이터 구현이다. 실망에서의 계측·제어 지연과 예측 오차는 별도 검증이 필요하다.',
        '- 큐 스냅샷 기반 배출 추정이며 임의의 이후 트래픽에서도 성립하는 보장은 아니다. 라우팅 표 갱신 뒤 2~3ns 순서를 두고 제어한다.',
        '- 처리량은 누적 ACK 기준이고 RTT p95는 시간가중 LastRTT 분포다. 전환 주변의 불필요 재전송은 TCP 재전송 콜백과 원본 수신 시각으로 확인했다.',
        '- 송신기에서 대기를 적용한 경우 TCP 재전송 판단 시각과 실제 IP 송신 시각을 구분하여 증거를 대조했다.',
        '- 초기 공통 RTO/손실은 개선 대상이 아니다. 표는 전환 주변 구간이며, 전환 이전 기록이 동일한지 비교했다.',
        '- 대기 버퍼를 켠 조건은 장치 q100 외에 추가 메모리를 사용한다. 원래 TcDrop 추적과 TCP 손실 판정 소스는 유지했다.','',
        '재현: prepare.py(컨테이너) → run.py build → run.py train → analyze.py train → run.py heldout → analyze.py heldout → run.py restore.',
        '입력/코드 해시: provenance.json. 고정한 선택: selection.json. 새 경로 원본: sydney_state.zip. 원본 소스 복원 확인: restore_verification.json.']
    (HERE/'실험결과.txt').write_text('\n'.join(lines)+'\n',encoding='utf-8-sig')

def plot(plan,chosen_label='선택한 v2'):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    plt.rcParams.update({'font.family':'Malgun Gothic','axes.unicode_minus':False,'font.size':9})
    curves=json.loads((HERE/'train_plot_data.json').read_text())|json.loads((HERE/'heldout_plot_data.json').read_text())
    chosen=json.loads((HERE/'selection.json').read_text())['chosen']
    fig,axes=plt.subplots(3,4,figsize=(17,10),sharex='col',constrained_layout=True)
    for j,e in enumerate(plan['events']):
        city=e['city']
        for mode in ('baseline','pace' if city=='sydney' else 'early',chosen):
            d=curves[city][mode];label=chosen_label if mode==chosen else ('페이싱만' if mode=='pace' else '기본 방식' if mode=='baseline' else '전환만 앞당김')
            for i,key in enumerate(('extra_ack_MB','cwnd','rtt')):axes[i,j].plot(d['offset_s'],d[key],label=label,linewidth=1.2)
        axes[0,j].set_title(NAMES[city]+(' · 별도 검증' if city=='sydney' else ''))
        axes[0,j].legend(fontsize=8);axes[2,j].set_xlabel('원래 전환 시점 기준 (초)')
        for i,label in enumerate(('기본 대비 추가 ACK (MB)','cwnd (MSS)','최근 RTT (ms)')):
            axes[i,j].set_ylabel(label);axes[i,j].grid(alpha=.2);axes[i,j].axvline(0,color='gray',linestyle=':')
    fig.savefig(HERE/'overview.png',dpi=160);plt.close(fig)

if __name__=='__main__':evaluate(sys.argv[1] if len(sys.argv)>1 else 'train')
