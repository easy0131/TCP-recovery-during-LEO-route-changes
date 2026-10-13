"""Verify routing pilot traces and compare common observation intervals."""
from bisect import bisect_right
from collections import Counter, defaultdict
import csv
import json
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT/'team_share_recheck'))
from analyze import packet, rows, trace

MSS = 1380
LABELS = dict(immediate='즉시 전환', delay_2ms='2 ms 기준', delay_5ms='5 ms 기준',
              delay_10ms='10 ms 기준', valid_hold='유효한 동안 유지')


def series(records):
    times, values = zip(*records)
    assert all(a <= b for a,b in zip(times,times[1:]))
    return list(times), list(values)


def at(data, t):
    times, values = data
    i = bisect_right(times,t)-1
    assert i >= 0, ('No value at interval start', t)
    return values[i]


def weighted(data, start, end):
    """Time distribution of the most recently recorded value, not ACK counts."""
    times, values = data
    i = bisect_right(times,start)-1
    assert i >= 0 and start < end
    weights = defaultdict(int)
    while i < len(times) and times[i] < end:
        a = max(start,times[i])
        b = min(end,times[i+1] if i+1 < len(times) else end)
        if b > a:
            weights[values[i]] += b-a
        i += 1
    assert sum(weights.values()) == end-start
    result, cumulative = {}, 0
    for value, weight in sorted(weights.items()):
        cumulative += weight
        for name, q in [('median',0.5),('p95',0.95)]:
            if name not in result and cumulative >= (end-start)*q:
                result[name] = value
    result['mean'] = sum(v*w for v,w in weights.items())/(end-start)
    return result


def load(name=None, folder=None):
    assert name is not None or folder is not None
    folder = Path(folder) if folder is not None else ROOT/'runs'/('route_policy_london26_q100_'+name)
    assert (folder/'logs_ns3/finished.txt').read_text().strip() == 'Yes', name
    for file in ('diagnostic_coverage.txt','hop_coverage.txt'):
        content = (folder/file).read_text()
        assert 'completed=1' in content and 'missing_required=0' in content
    assert 'changed_queue_objects=0' in (folder/'hop_coverage.txt').read_text()
    raw = {key:trace(folder/f'logs_ns3/tcp_flow_0_{key}.csv') for key in ('cwnd','rtt','progress')}
    last_rows = rows(folder/'diagnostic_last_rtt.csv')
    assert len({(r['node'],r['socket_index']) for r in last_rows}) == 1, 'RTT mixed across flows'
    last = [(int(r['time_ns']),int(r['rtt_ns'])) for r in last_rows]
    data = {key:series([(r[1],r[2]) for r in raw[key]]) for key in raw}
    data['last_rtt'] = series(last)
    assert all(a <= b for a,b in zip(data['progress'][1],data['progress'][1][1:]))
    drops = rows(folder/'hop_drops.csv')
    states = rows(folder/'diagnostic_states.csv')
    rtos = [int(x) for x in re.findall(r'LAB1_RTO_ENTRY time_ns=(\d+)',(folder/'console.log').read_text())]
    assert rtos == [int(r['time_ns']) for r in states if r['node']=='1584' and r['new_state']=='4']
    assert all(at(data['cwnd'],t) == MSS for t in rtos)
    retxs = [{k:int(v) for k,v in r.items()} for r in rows(folder/'diagnostic_retransmissions.csv')]
    assert {(str(r['node']),str(r['socket_index'])) for r in retxs} <= {(r['node'],r['socket_index']) for r in last_rows}
    return dict(folder=folder,raw=raw,data=data,drops=drops,states=states,rtos=rtos,retxs=retxs)


def interval(run, start, end):
    a,b = round(start*1e9), round(end*1e9)
    progress = run['data']['progress']
    assert b <= progress[0][-1]
    acked = at(progress,b)-at(progress,a)
    result = dict(start_s=start,end_s=end,acked_MB=acked/1e6,ack_mbps=acked*8/(b-a)*1000,
        tc_drops=sum(a <= int(r['time_ns']) < b and r['event']=='TcDrop' for r in run['drops']),
        rtos=sum(a <= t < b for t in run['rtos']),
        retransmissions=sum(a <= r['time_ns'] < b for r in run['retxs']),
        recovery_entries=sum(a <= int(r['time_ns']) < b and r['new_state']=='3' for r in run['states']))
    for key in ('rtt','last_rtt'):
        observed_start = max(a,run['data'][key][0][0])
        result.update({key+'_'+stat+'_ms':v/1e6 for stat,v in weighted(run['data'][key],observed_start,b).items()})
        result[key+'_observed_s'] = (b-observed_start)/1e9
    first_cwnd = run['data']['cwnd'][0][0]
    result['cwnd_before_mss'] = at(run['data']['cwnd'],a-1)/MSS if a > first_cwnd else None
    result['cwnd_min_mss'] = min([at(run['data']['cwnd'],max(a,first_cwnd))] +
        [v for t,v in zip(*run['data']['cwnd']) if a <= t < b])/MSS
    return result


def packet_evidence(run, windows, transitions):
    """Use explicit TCP retransmission notifications, then match endpoint copies."""
    rx, tx = defaultdict(list), defaultdict(list)
    reorder = []
    highest, window_index = -1, -1
    retx_keys = {(r['time_ns'],r['seq'],r['payload_bytes']) for r in run['retxs']}
    with (run['folder']/'diagnostic_packets.csv').open(newline='') as f:
        for row in csv.DictReader(f):
            if row['event'] not in ('ip_tx','ip_rx'):
                continue
            if not any(a*1e9 <= int(row['time_ns']) <= b*1e9 for a,b in windows):
                continue
            p = packet(row)
            if not p['payload']:
                continue
            if p['node']==1584 and p['event']=='ip_tx':
                tx[p['seq']].append(p)
            if p['node']==1585 and p['event']=='ip_rx':
                rx[p['seq']].append(p)
                original = next((q for q in tx[p['seq']] if q['identity']==p['identity'] and
                    (q['time_ns'],q['seq'],q['payload']) not in retx_keys),None)
                if original:
                    wi = next(i for i,(a,b) in enumerate(windows) if a*1e9 <= p['time_ns'] <= b*1e9)
                    if wi != window_index:
                        highest, window_index = -1, wi
                    if p['seq'] < highest:
                        reorder.append(p['time_ns'])
                    highest = max(highest,p['seq'])
    evidence = []
    for r in run['retxs']:
        t,seq = r['time_ns'],r['seq']
        if not any(a*1e9 <= t <= b*1e9 for a,b in windows):
            continue
        attempts = tx[seq]
        current = [p for p in attempts if p['time_ns']==t and p['payload']==r['payload_bytes']]
        assert len(current)==1, ('Missing endpoint retransmission',seq,t)
        originals = [p for p in attempts if p['time_ns']<t and
                     (p['time_ns'],seq,p['payload']) not in retx_keys]
        original_arrivals = [p for p in rx[seq] if any(p['identity']==q['identity'] for q in originals)]
        prior_rx = [p for p in rx[seq] if p['time_ns']<t and p['payload']==r['payload_bytes']]
        status = 'original_received_before_retransmission' if any(p['time_ns']<t for p in original_arrivals) else (
            'data_received_before_retransmission' if prior_rx else 'not_proven_already_received')
        evidence.append(dict(time_s=t/1e9,seq=seq,status=status,
            original_rx_s=min((p['time_ns']/1e9 for p in original_arrivals),default=None)))
    summaries = []
    for t in transitions:
        selected = [e for e in evidence if t <= e['time_s'] < t+2]
        summaries.append(dict(switch_s=t,post2_reordered_original_arrivals=sum(t*1e9<=x<(t+2)*1e9 for x in reorder),
            post2_retransmissions=len(selected),post2_retransmission_status=dict(Counter(e['status'] for e in selected))))
    return evidence,summaries


def main():
    assert weighted(([0,10,10,20],[1,9,2,3]),0,30) == dict(median=2,p95=3,mean=2.0)
    assert at(([0,10,10],[1,2,3]),10) == 3
    plan = json.loads((HERE/'plan.json').read_text())
    names = list(dict.fromkeys(plan['aliases'].values()))
    runs = {name:load(name) for name in names}
    baseline = runs['immediate']
    checks = []
    for name,run in runs.items():
        assert run['data']['progress'][0][-1] == plan['stop_s']*1e9
        for metric in ('cwnd','rtt','progress'):
            before = lambda r: [x for x in r['raw'][metric] if x[1] < 26.2e9]
            assert before(run)==before(baseline), (name,metric,'Pre-intervention mismatch')
        assert [r for r in run['drops'] if int(r['time_ns'])<26.2e9] == [r for r in baseline['drops'] if int(r['time_ns'])<26.2e9]
    checks.append('All conditions identical before 26.2 s: cwnd, SRTT, cumulative ACKs, every drop row')
    for first,second,until in [('immediate','delay_2ms',121.5),('immediate','delay_5ms',75),('delay_10ms','valid_hold',92.6)]:
        for metric in ('cwnd','rtt','progress'):
            assert [r for r in runs[first]['raw'][metric] if r[1]<until*1e9] == [r for r in runs[second]['raw'][metric] if r[1]<until*1e9], (first,second,metric)
    checks.append('Policies with equal route histories have identical cwnd/SRTT/ACK traces until their first differing decision')
    for metric in ('cwnd','rtt','progress'):
        reference = trace(ROOT/f'runs/baseline_q100_100s/logs_ns3/tcp_flow_0_{metric}.csv')
        assert [r for r in baseline['raw'][metric] if r[1]<100e9] == [r for r in reference if r[1]<100e9]
    checks.append('Expanded passive observers reproduce the original immediate baseline through 100 s')
    routing = rows(HERE/'routing.csv')
    summaries, switch_metrics, packet_summaries = [], [], {}
    common_windows = [(24.2,26.2),(26.2,28.2),(26.2,36.2),(26.2,46.2),
                      (26.2,121.5),(26.2,plan['stop_s']),(0,plan['stop_s'])]
    for name,run in runs.items():
        for a,b in common_windows:
            result = dict(policy=name,**interval(run,a,b))
            selected = [r for r in routing if r['policy']==name and a <= float(r['time_s']) < b]
            result['mean_extra_propagation_rtt_ms'] = sum(float(r['extra_rtt_prop_ms']) for r in selected)/len(selected)
            result['max_extra_propagation_rtt_ms'] = max(float(r['extra_rtt_prop_ms']) for r in selected)
            result['switches'] = sum(a<=e['time_s']<b for e in plan['events'][name])
            summaries.append(result)
        switches = [e['time_s'] for e in plan['events'][name] if e['time_s'] < plan['stop_s']]
        for t in switches:
            s = dict(policy=name,**interval(run,t,t+2))
            cw = list(zip(*run['data']['cwnd']))
            local = [(time,value) for time,value in cw if t*1e9<=time<(t+2)*1e9]
            minimum = min([at(run['data']['cwnd'],t*1e9)]+[v for _,v in local])
            lowest_at = next((time for time,value in local if value==minimum),round(t*1e9))
            s['cwnd_fell_below_pre_switch'] = minimum < s['cwnd_before_mss']*MSS
            recovered = next((time for time,value in cw if time>lowest_at and value>=s['cwnd_before_mss']*MSS),None)
            s['cwnd_first_return_to_pre_switch_s'] = recovered/1e9 if recovered and s['cwnd_fell_below_pre_switch'] else None
            s['cwnd_first_return_delay_s'] = recovered/1e9-t if recovered and s['cwnd_fell_below_pre_switch'] else None
            switch_metrics.append(s)
        evidence, packet_summaries[name] = packet_evidence(run,plan['packet_windows_s'],switches)
        (HERE/(name+'_retransmission_evidence.json')).write_text(json.dumps(evidence,indent=2))
    assert packet_summaries['immediate'][0]['post2_retransmissions'] == 28
    assert packet_summaries['immediate'][0]['post2_retransmission_status'] == {'original_received_before_retransmission':28}
    checks.append('Original London 26.2 s event independently reproduced: 28/28 retransmissions after original delivery')
    for filename,records in [('comparison.csv',summaries),('switch_windows.csv',switch_metrics)]:
        with (HERE/filename).open('w',newline='',encoding='utf-8-sig') as f:
            writer=csv.DictWriter(f,fieldnames=list(records[0]));writer.writeheader();writer.writerows(records)
    result = dict(plan=plan,checks=checks,common_windows=summaries,switch_windows=switch_metrics,
                  packet_summaries=packet_summaries,
                  rtt_definition='Time-weighted distribution of latest TCP LastRTT (and SRTT); not per-packet RTT CDF')
    (HERE/'results.json').write_text(json.dumps(result,indent=2))
    write_report(result)
    plot(runs,plan,routing)
    print(json.dumps(dict(checks=checks,primary=[s for s in summaries if s['start_s']==26.2 and s['end_s']==plan['stop_s']]),indent=2))


def write_report(result):
    plan = result['plan']
    selected = [s for s in result['common_windows'] if s['start_s']==26.2 and s['end_s']==plan['stop_s']]
    base = next(s for s in selected if s['policy']=='immediate')
    control = next(s for s in selected if s['policy']=='delay_2ms')
    best = max(selected,key=lambda s:s['ack_mbps'])
    lines = ['London q100 경로 전환 정책 1차 실험', '2026-10-06', '',
        '핵심 결과:',
        f'- 이 조건에서는 {LABELS[best["policy"]]}의 ACK 처리량이 가장 높았다. 즉시 전환 대비 '
        f'{(best["ack_mbps"]/base["ack_mbps"]-1)*100:.2f}% 증가, 추가 ACK {best["acked_MB"]-base["acked_MB"]:.3f}MB.',
        f'- 대신 최근 RTT 중앙값은 {base["last_rtt_median_ms"]:.0f}→{best["last_rtt_median_ms"]:.0f}ms, '
        f'p95는 {base["last_rtt_p95_ms"]:.0f}→{best["last_rtt_p95_ms"]:.0f}ms로 증가했다.',
        '- 10ms 조건은 92.6초에, 유효성 유지 조건은 121.5초에 전환하며 각각 불필요한 재전송 43개, 48개가 발생했다.',
        '- 따라서 전환을 줄이면 처리량이 좋아질 수 있으나, 전환 순간의 재정렬 문제까지 해결한 것은 아니다.',
        '- 2ms 조건은 이 사례에서 즉시 전환과 121.5초까지 동일했다. 이후 차이는 0.1초 사전 전환에서 발생했다.',
        f'- 같은 사전 전환 규칙을 쓰는 2ms 조건 대비, 유효성 유지 조건의 전체 평가 구간 처리량 이득은 '
        f'{(best["ack_mbps"]/control["ack_mbps"]-1)*100:.2f}%이다. 즉시 대비 이득 전체를 전환 횟수 감소의 효과로 해석하면 안 된다.',
        '- 단일 조건의 탐색 결과이며 최적 임계값을 확정하지 않는다. 다음 검증은 뉴욕 경로 등 별도 조건에서 수행한다.', '',
        '조건: ns-3.48, CUBIC, pacing=false, 양방향 큐 100패킷, 100 Mbps, 단일 흐름·동일 시드.',
        '26.2초 이전에는 모두 원래 라우팅을 사용하고, 이후 각 정책을 100ms마다 적용했다.',
        '지연 조건은 같은 시점의 기존 경로와 원래 라우팅 후보의 정방향+역방향 전파 지연 차이이다.',
        '2/5/10ms보다 이득이 클 때 전환한다. 유지 정책은 다음 100ms 시점에 경로가 무효가 되면 미리 전환한다.',
        '필요하면 이미 주어진 다음 스냅샷의 경로를 100ms 먼저 사용한다. 현재와 다음 시점의 유효성을 검사했다.',
        '따라서 즉시 전환 원본의 121.6초 전환과 개선군의 121.5초 전환은 구분해야 한다.',
        f'기존 경로의 최초 무효 표본은 {plan["first_old_route_invalid_sample_s"]:.1f}초. 모든 실행을 {plan["stop_s"]}초까지 완료했다.', '',
        f'공통 평가 구간: 26.2~{plan["stop_s"]}초 (미뤄진 전환 이후 포함)',
        '정책 | ACK 처리량(Mbps) | 즉시 대비 추가 ACK(MB) | 최근 RTT 중앙값/p95(ms) | 평균/최대 추가 전파 RTT(ms) | TcDrop | 재전송 | RTO | 전환 수']
    for s in selected:
        lines.append(f'{LABELS[s["policy"]]} | {s["ack_mbps"]:.3f} | {s["acked_MB"]-base["acked_MB"]:+.3f} | '
            f'{s["last_rtt_median_ms"]:.3f}/{s["last_rtt_p95_ms"]:.3f} | '
            f'{s["mean_extra_propagation_rtt_ms"]:.3f}/{s["max_extra_propagation_rtt_ms"]:.3f} | '
            f'{s["tc_drops"]} | {s["retransmissions"]} | {s["rtos"]} | {s["switches"]}')
    lines += ['', '초기 10초(26.2~36.2초):']
    for s in result['common_windows']:
        if s['start_s']==26.2 and s['end_s']==36.2:
            lines.append(f'{LABELS[s["policy"]]}: {s["ack_mbps"]:.3f} Mbps, 최근 RTT 중앙값 {s["last_rtt_median_ms"]:.3f} ms, TcDrop {s["tc_drops"]}, 재전송 {s["retransmissions"]}')
    lines += ['', '사전 전환 시점 차이가 개입하기 전 공통 구간(26.2~121.5초):']
    for s in result['common_windows']:
        if s['start_s']==26.2 and s['end_s']==121.5:
            lines.append(f'{LABELS[s["policy"]]}: {s["ack_mbps"]:.3f} Mbps, 최근 RTT 중앙값/p95 '
                         f'{s["last_rtt_median_ms"]:.0f}/{s["last_rtt_p95_ms"]:.0f} ms')
    lines.append('이 구간만으로는 유효성 유지 정책의 미뤄진 전환 비용이 빠지므로, 전체 구간 결과와 함께 해석한다.')
    lines += ['', '실제 전환 시점 및 사유:']
    for name in LABELS:
        events = [e for e in plan['events'][name] if e['time_s']<plan['stop_s']]
        lines.append(LABELS[name]+': '+', '.join(f'{e["time_s"]:.1f}초 ({e["reason"]}, 전파 RTT 이득 {e["improvement_ms"]:+.3f}ms)' for e in events))
    lines += ['', '각 전환 직후 2초:']
    for s in result['switch_windows']:
        name = s['policy']; p = next(p for p in result['packet_summaries'][name] if p['switch_s']==s['start_s'])
        proven = sum(v for k,v in p['post2_retransmission_status'].items() if k.endswith('received_before_retransmission'))
        lines.append(f'{LABELS[name]} {s["start_s"]:.1f}초: TcDrop {s["tc_drops"]}, RTO {s["rtos"]}, '
            f'재전송 {s["retransmissions"]}개 중 이미 수신됨을 증명한 것 {proven}개, '
            f'원본 역전 도착 {p["post2_reordered_original_arrivals"]}개, cwnd {s["cwnd_before_mss"]:.0f}→최저 {s["cwnd_min_mss"]:.0f} MSS')
        lines.append('  전환 직전 cwnd로 처음 돌아온 시각: '+('해당 없음(직후 2초에 전환 직전 값 아래로 감소하지 않음)' if not s['cwnd_fell_below_pre_switch'] else
            f'{s["cwnd_first_return_to_pre_switch_s"]:.6f}초' if s['cwnd_first_return_to_pre_switch_s'] else '관측 종료까지 없음'))
    lines += ['', '검증:', *['- '+s for s in result['checks']], '', '해석 범위:',
        '- 처리량은 누적 ACK 기반이며 수신 애플리케이션 goodput과 구분한다.',
        '- RTT 대표값은 ns-3 LastRTT의 최근 측정값을 시간에 따라 유지하여 계산한 시간가중 분포이다. 패킷별 RTT 분포가 아니다.',
        '- 기존 rtt.csv는 SRTT이며 별도 수치로 comparison.csv에 제공한다. RTT 증가는 큐잉 변화도 포함한다.',
        '- 링크 거리와 유효성은 100ms 표본에서 검사했다. 실제 장비의 연결 설정 시간이나 연속 시간 가시성을 재현한 실험은 아니다.',
        '- 개선 정책은 시험 흐름의 정·역방향 경로 항목만 유지한다. 나머지 라우팅 갱신은 계속 적용한다.',
        '- 경로 변경 횟수가 적다고 단일 전환의 재정렬이나 혼잡이 사라지는 것은 아니다.',
        '- cwnd 첫 복귀는 전환 직후 2초의 최솟값 이후 전환 직전 값 이상이 처음 된 시각이며, 처리량의 지속적인 회복을 뜻하지 않는다.',
        '- 단일 지상국 쌍·큐·시드·시작 시점 결과이다. 다른 조건으로 일반화하지 않는다.',
        '- 표의 RTO 0건은 26.2초 이후 평가 구간 값이다. 모든 조건에 공통인 초반 RTO를 없앤 결과가 아니다.',
        '- 이득이 일정 시간 지속될 때 전환하는 조건은 이번 단계에서 시험하지 않았다.',
        '- TCP 코드와 팀 TcDrop 코드는 공유본 그대로다. main에는 관측 시간 확장, LastRTT·Retransmission 수집만 추가했다.',
        '- 상세 패킷 기록 범위: '+str(plan['packet_windows_s']),
        '- 손실·재전송 알림·TCP 상태·최근 RTT 기록은 전체 실행을 포함한다.', '',
        '재현: prepare.py(과제 컨테이너) → run.py(Windows) → analyze.py(Windows, matplotlib 설치된 Python).',
        '원자료: ../runs/route_policy_london26_q100_*; 조건·출처: plan.json, provenance.json, passive_observation.patch.',
        '수치: comparison.csv, switch_windows.csv, results.json; 경로: routing.csv, policy_states.zip; 그림: overview.png.']
    (HERE/'실험결과.txt').write_text('\n'.join(lines)+'\n',encoding='utf-8-sig')


def plot(runs,plan,routing):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    plt.rcParams.update({'font.family':'Malgun Gothic','axes.unicode_minus':False,'font.size':10})
    fig,axes = plt.subplots(3,1,figsize=(12,10),sharex=True,constrained_layout=True)
    # 100 ms bins; smooth the displayed throughput with non-overlapping 1 s bins.
    for name,run in runs.items():
        p = run['data']['progress']
        xs = list(range(24,plan['stop_s']))
        rates = [(at(p,(x+1)*1e9)-at(p,x*1e9))*8/1e6 for x in xs]
        axes[0].plot([x+0.5 for x in xs],rates,label=LABELS[name],linewidth=1.2)
        ts = [round((24+i*.1)*1e9) for i in range(round((plan['stop_s']-24)*10))]
        axes[1].plot([t/1e9 for t in ts],[at(run['data']['last_rtt'],t)/1e6 for t in ts],linewidth=1.2)
        axes[2].plot([t/1e9 for t in ts],[at(run['data']['cwnd'],t)/MSS for t in ts],linewidth=1.2)
    axes[0].set_title('London · q100 · 경로 전환 정책 비교 (동일 시드 1회씩)')
    axes[0].set_ylabel('ACK 처리량\n(Mbps, 1초 구간)')
    axes[1].set_ylabel('최근 RTT 측정값\n(ms)')
    axes[2].set_ylabel('cwnd (MSS)')
    axes[2].set_xlabel('시뮬레이션 시간 (초)')
    axes[0].legend(ncol=3,loc='lower right',fontsize=9)
    for ax in axes:
        ax.grid(alpha=.2)
        for t in (26.2,75,92.6,121.5):
            ax.axvline(t,color='gray',linestyle=':',linewidth=.8)
        ax.set_xlim(24,plan['stop_s'])
    fig.savefig(HERE/'overview.png',dpi=170)
    plt.close(fig)


if __name__ == '__main__':
    main()
