"""Compare paired timing cases and inspect packets crossing each transition."""
from collections import Counter
import csv
import importlib.util
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent
ROOT=HERE.parent
spec=importlib.util.spec_from_file_location('pilot_analysis',ROOT/'route_policy_pilot/analyze.py')
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
LABELS={'london_advance0':'기존 121.6초',
    'london_advance100':'100ms 전 · 활성 경로 먼저',
    'london_advance200':'200ms 전 · 활성 경로 먼저',
    'london_advance100_full_update':'100ms 전 · 전체 갱신 함께',
    'newyork_advance0':'기존 48.9초','newyork_delay100':'100ms 뒤','newyork_delay200':'200ms 뒤'}


def crossing_packets(run,case):
    """Endpoint evidence; transmit time is not a claim about every traversed hop."""
    switch=round(case['switch_s']*1e9)
    nominal=round(case['event_s']*1e9)
    lo,hi=switch-800_000_000,switch+2_000_000_000
    retx={(r['time_ns'],r['seq'],r['payload_bytes']) for r in run['retxs']}
    sent,arrivals={},[]
    with (run['folder']/'diagnostic_packets.csv').open(newline='') as f:
        for row in csv.DictReader(f):
            t=int(row['time_ns'])
            if not lo<=t<hi or row['event'] not in ('ip_tx','ip_rx'):
                continue
            q=p.packet(row)
            if q['payload']==0:continue
            if q['event']=='ip_tx' and q['node']==1584 and (t,q['seq'],q['payload']) not in retx:
                sent[q['identity']]=q
            if q['event']=='ip_rx' and q['node']==1585 and q['identity'] in sent:
                arrivals.append(dict(seq=q['seq'],tx_ns=sent[q['identity']]['time_ns'],rx_ns=t))
    pre=[a for a in arrivals if a['tx_ns']<switch]
    post=[a for a in arrivals if a['tx_ns']>=switch]
    first_post=min((a['rx_ns'] for a in post),default=None)
    overtaken=[a for a in pre if first_post is not None and a['rx_ns']>first_post and
               any(b['seq']>a['seq'] and b['rx_ns']<a['rx_ns'] for b in post)]
    inversions=[];highest=None
    for a in arrivals:
        if highest is not None and a['seq']<highest['seq']:
            inversions.append(dict(late=a,earlier_arrival=highest))
        if highest is None or a['seq']>highest['seq']:highest=a
    local_inversions=[v for v in inversions if switch<=v['late']['rx_ns']<hi]
    bursts=Counter(q['time_ns'] for q in sent.values() if switch<=q['time_ns']<hi)
    burst_time,burst_size=max(bursts.items(),key=lambda x:x[1]) if bursts else (None,0)
    dropped=[r for r in run['drops'] if r['event']=='TcDrop' and switch<=int(r['time_ns'])<hi]
    return dict(pre_sent_originals_arriving_after_switch=sum(a['rx_ns']>=switch for a in pre),
        pre_sent_originals_arriving_after_nominal=sum(a['rx_ns']>=nominal for a in pre),
        first_post_sent_original_rx_s=first_post/1e9 if first_post else None,
        last_pre_sent_original_rx_s=max((a['rx_ns']/1e9 for a in pre),default=None),
        pre_sent_originals_overtaken_by_post_sent=len(overtaken),
        reordered_pairs_both_sent_before_switch=sum(v['late']['tx_ns']<switch and v['earlier_arrival']['tx_ns']<switch for v in local_inversions),
        reordering_examples=local_inversions[:5],
        overtaken_examples=[dict(seq=a['seq'],tx_s=a['tx_ns']/1e9,rx_s=a['rx_ns']/1e9) for a in overtaken[:5]],
        max_same_time_original_tx_burst_packets=burst_size,
        max_burst_time_s=burst_time/1e9 if burst_time else None,
        first_tc_drop_s=min((int(r['time_ns'])/1e9 for r in dropped),default=None))


def recovery(run,t):
    a=round(t*1e9); before=p.at(run['data']['cwnd'],a-1)
    samples=list(zip(*run['data']['cwnd']))
    local=[(ns,v) for ns,v in samples if a<=ns<a+2_000_000_000]
    minimum=min([p.at(run['data']['cwnd'],a)]+[v for _,v in local])
    if minimum>=before:
        return dict(cwnd_fell=False,cwnd_recovery_delay_s=0.0)
    at_min=next(ns for ns,v in local if v==minimum)
    restored=next((ns for ns,v in samples if ns>at_min and v>=before),None)
    return dict(cwnd_fell=True,cwnd_recovery_delay_s=(restored-a)/1e9 if restored else None)


def main():
    assert p.weighted(([0,10,10,20],[1,9,2,3]),0,30)==dict(median=2,p95=3,mean=2.0)
    assert recovery({'data':{'cwnd':([0,5,10,15,20],[100,90,70,90,100])}},5e-9)==dict(cwnd_fell=True,cwnd_recovery_delay_s=15e-9)
    assert recovery({'data':{'cwnd':([0,5,10],[100,100,110])}},5e-9)==dict(cwnd_fell=False,cwnd_recovery_delay_s=0.0)
    plan=json.loads((HERE/'plan.json').read_text())
    index={r['case']:ROOT/r['folder'] for r in json.loads((HERE/'runs.json').read_text())}
    cases=[c for c in plan['cases'] if c['valid']]
    checks,metrics,event_metrics,mechanisms,curves=[],[],[],{},{}
    for city in ('london','newyork'):
        selected=[c for c in cases if c['city']==city]
        runs={c['name']:p.load(folder=index[c['name']]) for c in selected}
        base=runs[city+'_advance0']
        earliest=min(c['switch_s'] for c in selected)
        common_end=max(c['switch_s'] for c in selected)+10
        for case in selected:
            name=case['name'];run=runs[name];t=case['switch_s']
            assert run['data']['progress'][0][-1]==case['stop_s']*1e9
            for key in ('cwnd','rtt','progress'):
                assert [r for r in run['raw'][key] if r[1]<earliest*1e9]==[r for r in base['raw'][key] if r[1]<earliest*1e9],(name,key)
            assert [r for r in run['drops'] if int(r['time_ns'])<earliest*1e9]==[r for r in base['drops'] if int(r['time_ns'])<earliest*1e9],name
            for kind,a,b in [('primary_common',earliest,common_end),
                    ('nominal_post10',case['event_s'],case['event_s']+10),
                    ('own_post10',t,t+10),('through_end',earliest,case['stop_s'])]:
                metrics.append(dict(case=name,city=city,window=kind,**p.interval(run,a,b)))
            window_text=next(line.split('=',1)[1] for line in (run['folder']/'diagnostic_coverage.txt').read_text().splitlines()
                if line.startswith('packet_window_seconds='))
            recorded_windows=[list(map(float,part.split('..'))) for part in window_text.split(' and ')]
            assert any(a<=t and t+2<=b for a,b in recorded_windows),'Missing transition packet coverage'
            evidence,events=p.packet_evidence(run,recorded_windows,[t])
            ev=events[0];m=p.interval(run,t,t+2)
            assert ev['post2_retransmissions']==m['retransmissions']
            m.update(case=name,city=city,**recovery(run,t),**ev)
            m['proven_unnecessary_retransmissions']=sum(v for k,v in ev['post2_retransmission_status'].items() if k.endswith('received_before_retransmission'))
            assert m['proven_unnecessary_retransmissions']<=m['retransmissions']
            event_metrics.append(m)
            (HERE/(name+'_retransmission_evidence.json')).write_text(json.dumps(evidence,indent=2))
            mechanisms[name]=crossing_packets(run,case)
            xs=[round((earliest-1+i*.1)*1e9) for i in range(round((common_end-earliest+2)*10))]
            rate_x=[earliest-1+i*.25 for i in range(round((common_end-earliest+2)*4))]
            progress=run['data']['progress']
            curves[name]=dict(time_s=[x/1e9 for x in xs],
                cwnd_mss=[p.at(run['data']['cwnd'],x)/p.MSS for x in xs],
                rtt_ms=[p.at(run['data']['last_rtt'],x)/1e6 for x in xs],
                rate_time_s=[x+.125 for x in rate_x],
                ack_mbps=[(p.at(progress,round((x+.25)*1e9))-p.at(progress,round(x*1e9)))*8/.25/1e6 for x in rate_x])
            print('ANALYZED',name,'TcDrop',m['tc_drops'],'retx',m['retransmissions'],'proven unnecessary',m['proven_unnecessary_retransmissions'],flush=True)
        checks.append(f'{city}: all conditions have identical cwnd/SRTT/ACK/drop traces before {earliest:.1f} s')
        if city=='newyork':
            for key in ('cwnd','rtt','progress'):
                old=p.trace(ROOT/f'runs/team_share_ny_baseline_q100_60s/logs_ns3/tcp_flow_0_{key}.csv')
                assert [r for r in base['raw'][key] if r[1]<60e9]==[r for r in old if r[1]<60e9],key
            checks.append('New York baseline reproduces the teammate-diagnostics 60 s reference exactly')
        del runs
    result=dict(plan=plan,checks=checks,metrics=metrics,events=event_metrics,endpoint_mechanisms=mechanisms)
    (HERE/'results.json').write_text(json.dumps(result,indent=2))
    (HERE/'plot_data.json').write_text(json.dumps(curves))
    for filename,records in [('comparison.csv',metrics),('switch_windows.csv',event_metrics)]:
        with (HERE/filename).open('w',encoding='utf-8-sig',newline='') as f:
            writer=csv.DictWriter(f,fieldnames=list(records[0]));writer.writeheader();writer.writerows(records)
    report(result)
    plot(result,curves)
    print('PASS ALL TIMING COMPARISONS',flush=True)


def report(result):
    primary={m['case']:m for m in result['metrics'] if m['window']=='primary_common'}
    events={e['case']:e for e in result['events']}
    baseline=primary['london_advance0'];early=primary['london_advance100']
    bny=primary['newyork_advance0']
    lines=['경로 전환 시점 비교 · 2차 실험','2026-10-06','',
        '핵심 결론:',
        '- 런던에서는 새 경로를 먼저 쓰면서 기존 경로 중간 노드의 전달 설정을 잠시 유지한 방식에 효과가 있었다.',
        f'- 같은 121.5초에 전환해도 활성 경로만 먼저 바꾼 조건의 불필요한 재전송은 '
        f'{events["london_advance100"]["proven_unnecessary_retransmissions"]}개, 전체 라우팅 갱신을 함께 옮긴 조건은 '
        f'{events["london_advance100_full_update"]["proven_unnecessary_retransmissions"]}개였다(각 직후 2초).',
        f'- 활성 경로 100ms 조기 전환은 공통 10.2초 동안 처리량 {baseline["ack_mbps"]:.3f}→{early["ack_mbps"]:.3f}Mbps '
        f'({(early["ack_mbps"]/baseline["ack_mbps"]-1)*100:+.2f}%). 200ms도 비슷했다.',
        f'- 다만 같은 10.2초 전체의 TcDrop은 {baseline["tc_drops"]}→{early["tc_drops"]}개, RTT p95는 '
        f'{baseline["last_rtt_p95_ms"]:.0f}→{early["last_rtt_p95_ms"]:.0f}ms였다. 전환 직후 재전송을 피했다고 전체 혼잡까지 없어진 것은 아니다.',
        '- 1차의 2ms 조건 개선은 새 경로 도입과 기존 중간 노드 설정 유지가 함께 적용된 결과로 해석을 보완한다.',
        f'- 뉴욕의 지연 전환 처리량 차이는 100ms에서 {(primary["newyork_delay100"]["ack_mbps"]/bny["ack_mbps"]-1)*100:+.2f}%, '
        f'200ms에서 {(primary["newyork_delay200"]["ack_mbps"]/bny["ack_mbps"]-1)*100:+.2f}%. 불필요한 재전송은 모두 38개로 같고, 실제 드롭은 18→19개였다.',
        '- 따라서 이번 뉴욕 결과에서 전환 지연을 개선책으로 채택할 근거는 약하다. 새 경로가 유효해지기 전의 조기 전환은 별도로 제외했다.',
        '- 다음 후보는 새 경로 도입 시점을 고정하고, 기존 경로 중간 노드의 전달 설정을 유지하는 시간을 비교하는 것이다. 뉴욕으로의 효과 일반화는 아직 확인하지 않았다.','',
        'TCP CUBIC·q100·100Mbps·pacing=false·동일 시드 123456789. 경로 선택과 전환 시점을 구분한 실험.',
        '런던 기존 시점과 100ms 조기 활성 경로 전환은 1차 원자료를 재사용했다. 모든 라우팅 항목이 종료 시각까지 같은지 검증했다.',
        '추가로 런던 200ms 조기 전환, 런던 전체 갱신 100ms 조기 전환, 뉴욕 기존/100ms/200ms 지연을 실행했다.',
        '뉴욕은 100/200ms 사전 전환 시 새 경로가 유효하지 않아 실행하지 않았다. 지연 실험을 사전 전환의 성공 사례로 해석하면 안 된다.',
        '지속시간 조건과 TCP 손실 판정 수정은 적용하지 않았다.','']
    for city,label in [('london','런던'),('newyork','뉴욕')]:
        selected=[m for m in result['metrics'] if m['city']==city and m['window']=='primary_common']
        baseline=next(m for m in selected if m['case']==city+'_advance0')
        lines += [f'{label}: 공통 평가 {baseline["start_s"]:.1f}~{baseline["end_s"]:.1f}초',
            '조건 | ACK 처리량(Mbps) | 기존 대비(%) | 최근 RTT 중앙값/p95(ms) | TcDrop | RTO']
        for m in selected:
            lines.append(f'{LABELS[m["case"]]} | {m["ack_mbps"]:.3f} | {(m["ack_mbps"]/baseline["ack_mbps"]-1)*100:+.2f} | '
                f'{m["last_rtt_median_ms"]:.0f}/{m["last_rtt_p95_ms"]:.0f} | {m["tc_drops"]} | {m["rtos"]}')
        lines += ['','각 실제 전환 직후 2초:']
        for e in result['events']:
            if e['city']!=city:continue
            recovery_text='감소 없음' if not e['cwnd_fell'] else ('관측 종료까지 미복귀' if e['cwnd_recovery_delay_s'] is None else f'{e["cwnd_recovery_delay_s"]:.3f}초')
            lines.append(f'{LABELS[e["case"]]} ({e["switch_s"]:.1f}초): 재전송 {e["retransmissions"]}, 이미 수신된 원본/데이터 재전송 '
                f'{e["proven_unnecessary_retransmissions"]}, 원본 역전 도착 {e["post2_reordered_original_arrivals"]}, '
                f'TcDrop {e["tc_drops"]}, RTO {e["rtos"]}, cwnd {e["cwnd_before_mss"]:.0f}→최저 {e["cwnd_min_mss"]:.0f} MSS, '
                f'전환 직전 cwnd로 첫 복귀: {recovery_text}')
        lines += ['']
    lines += ['전환 중 원본 패킷 관측:','조건 | 전환 전 송신·전환 후 도착 | 전환 후 송신 패킷에 추월당한 수 | 둘 다 전환 전 송신된 패킷의 역전 | 한 시각에 송신된 원본 최대 묶음']
    for name,m in result['endpoint_mechanisms'].items():
        lines.append(f'{LABELS[name]} | {m["pre_sent_originals_arriving_after_switch"]} | '
            f'{m["pre_sent_originals_overtaken_by_post_sent"]} | {m["reordered_pairs_both_sent_before_switch"]} | {m["max_same_time_original_tx_burst_packets"]}')
    lines += ['','측정·해석 범위:',
        '- 활성 경로 먼저: 정/역방향 현재 흐름의 새 경로 항목만 앞당긴다. 기존 경로 밖 항목은 원래 갱신 시점까지 유지된다.',
        '- 전체 갱신 함께: 런던 121.6초의 34개 라우팅 갱신을 모두 121.5초로 옮긴다. 새 정/역방향 경로는 활성 경로 먼저 조건과 같다.',
        '- 런던 전체 갱신 대조군은 단순한 시점 차이와 기존 중간 노드의 전달 설정 유지 효과를 구분한다.',
        '- 정적 라우팅 검사: 121.5초에 활성 경로만 전환하면 기존 가지의 224→1585 전달이 남는다. 전체 갱신을 앞당기면 224→202→180→1585로 바뀐다.',
        '- 두 런던 조건의 신규 정/역방향 경로는 동일하다. 기존 가지의 변경이 이동 중인 패킷을 우회시킬 수 있다는 설명은 이 대조군과 라우팅 표에 근거한 해석이며, 홉별 패킷 실측은 아니다.',
        '- 기본 라우팅 간격은 100ms. 변경 구간 링크 유효성을 10ms 표본으로 확인했다. 실제 장비의 접속 설정 절차는 모델링하지 않는다.',
        '- 처리량은 ACK된 바이트 기준. 공통 구간은 가장 이른 전환부터 가장 늦은 전환 10초 후까지로 잡았다.',
        '- 짧은 구간의 ACK 처리량은 ACK가 몰려 도착하면 링크 속도 100Mbps를 넘는 값으로 나타날 수 있다.',
        '- 각 조건 자체 전환 후 10초, 기존 전환 시각 기준 10초, 종료까지의 수치도 comparison.csv에 저장했다.',
        '- RTT는 최신 LastRTT 값의 시간가중 분포이며 패킷별 RTT 분포가 아니다. SRTT는 CSV에 별도로 제공한다.',
        '- cwnd 복귀는 전환 직후 2초의 최저값 이후 전환 직전 값 이상으로 처음 돌아온 때. 지속적인 처리량 회복을 뜻하지 않는다.',
        '- 원본/재전송은 명시적 Retransmission 알림과 TCP/IP 패킷 식별자로 구분했다. 이미 수신됨이 확인된 것만 불필요한 재전송으로 집계했다.',
        '- 전환 전 송신이라는 분류만으로 패킷이 모든 홉에서 기존 경로를 통과했다고 단정하지 않는다. 종단 관측이며 홉별 추적은 아니다.',
        '- 표의 손실·RTO는 해당 구간 값이다. 모든 실행 초반의 공통 RTO를 해결한 실험이 아니다.',
        '- 단일 흐름·시드이며 오프셋 3개로 최적 전환 시점이나 통계적 일반성을 주장하지 않는다.','',
        '검증:',
        '- 런던: 모든 조건의 cwnd/SRTT/누적 ACK/드롭 기록이 최초 개입인 121.4초 전까지 동일했다.',
        '- 뉴욕: 모든 조건의 cwnd/SRTT/누적 ACK/드롭 기록이 최초 개입인 48.9초 전까지 동일했다.',
        '- 뉴욕 기준 조건은 기존 팀 진단코드의 60초 실험과 cwnd/SRTT/누적 ACK 기록이 일치했다.','',
        '재현: prepare.py(과제 컨테이너) → run.py(Windows) → analyze.py(matplotlib 있는 Windows Python).',
        '조건/출처: plan.json, provenance.json, passive_observation.patch, geometry.csv. 실행 위치: runs.json.',
        '수치/증거: comparison.csv, switch_windows.csv, results.json, *_retransmission_evidence.json. 그림: overview.png.']
    (HERE/'실험결과.txt').write_text('\n'.join(lines)+'\n',encoding='utf-8-sig')


def plot(result,curves):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    plt.rcParams.update({'font.family':'Malgun Gothic','axes.unicode_minus':False,'font.size':10})
    fig,axes=plt.subplots(3,2,figsize=(14,10),constrained_layout=True)
    for col,city in enumerate(('london','newyork')):
        cases=[c for c in result['plan']['cases'] if c['valid'] and c['city']==city]
        for case in cases:
            name=case['name'];d=curves[name]
            style='--' if case.get('switch_scope')=='whole_event' else '-'
            axes[0,col].plot(d['rate_time_s'],d['ack_mbps'],label=LABELS[name],linestyle=style)
            axes[1,col].plot(d['time_s'],d['rtt_ms'],linestyle=style)
            axes[2,col].plot(d['time_s'],d['cwnd_mss'],linestyle=style)
        for ax in axes[:,col]:
            ax.grid(alpha=.2)
            ax.axvline(cases[0]['event_s'],color='gray',linestyle=':',linewidth=.8)
        axes[0,col].set_title('런던 · 121.6초 전환' if city=='london' else '뉴욕 · 48.9초 전환')
        axes[0,col].legend(fontsize=8,loc='lower right')
        axes[2,col].set_xlabel('시뮬레이션 시간 (초)')
    for ax,label in zip(axes[:,0],('ACK 처리량 (Mbps, 0.25초)','최근 RTT (ms)','cwnd (MSS)')):ax.set_ylabel(label)
    fig.savefig(HERE/'overview.png',dpi=170)
    plt.close(fig)


if __name__=='__main__':main()
