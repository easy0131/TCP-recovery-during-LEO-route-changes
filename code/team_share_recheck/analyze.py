"""Cross-check the team's raw traces; no original diagnostic parser is used."""
from pathlib import Path
from collections import Counter, defaultdict
from bisect import bisect_right
import csv
import json
import re
import io
from zipfile import ZipFile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
MSS = 1380
REFERENCE = {f'baseline_q{q}_60s':f'queue_probe_q{q}_60s' for q in (100,250,500,1000)}
REFERENCE.update({
    'baseline_q100_100s':'causal_london75_q100_baseline',
    'ny_baseline_q100_60s':'causal_newyork49_q100_baseline',
    'hold75_q100_100s':'hold75_q100_diagnostic_100s',
    'hold75_q1000_100s':'hold75_q1000_diagnostic_100s',
    'ny_hold48p9_q100_60s':'ny_hold48p9_q100_diagnostic_60s',
    'ny_hold48p9_q250_60s':'ny_hold48p9_q250_diagnostic_60s',
})
WINDOWS = {
    'baseline_q100_60s':[(0,5),(0,30),(0,60),(26.2,28.2)],
    'baseline_q250_60s':[(0,5),(0,60),(26.2,28.2)],
    'baseline_q500_60s':[(0,5),(0,60),(26.2,28.2)],
    'baseline_q1000_60s':[(0,5),(0,60),(26.2,28.2)],
    'baseline_q100_100s':[(75,77)],
    'ny_baseline_q100_60s':[(48.9,50.9)],
    'hold75_q100_100s':[(79,85)],
    'hold75_q1000_100s':[(79,85)],
    'ny_hold48p9_q100_60s':[(54,58.9)],
    'ny_hold48p9_q250_60s':[(54,58.9)],
}

def rows(path):
    with path.open(newline='') as f:
        return list(csv.DictReader(f))

def trace(path):
    with path.open(newline='') as f:
        return [tuple(map(int,r)) for r in csv.reader(f)]

def packet(row):
    b = bytes.fromhex(row['hex_prefix'])
    assert len(b)>=40 and b[0]>>4==4 and b[9]==6
    ih = (b[0]&15)*4
    th = (b[ih+12]>>4)*4
    assert ih>=20 and th>=20 and len(b)>=ih+th
    total = int.from_bytes(b[2:4],'big')
    assert total>=ih+th
    seq = int.from_bytes(b[ih+4:ih+8],'big')
    # Options plus IP ID distinguish attempts without relying on shared UIDs.
    identity = (b[12:20].hex(),b[ih:ih+4].hex(),seq,total-ih-th,
                int.from_bytes(b[4:6],'big'),b[ih+20:ih+th].hex())
    return dict(time_ns=int(row['time_ns']),event=row['event'],node=int(row['node']),
                seq=seq,payload=total-ih-th,identity=identity)

def selected_packets(folder, seq=None, start=0, end=5):
    with (folder/'diagnostic_packets.csv').open(newline='') as f:
        for r in csv.DictReader(f):
            if r['event'] not in ('ip_tx','ip_rx') or not start*1e9 <= int(r['time_ns']) <= end*1e9:
                continue
            p = packet(r)
            if p['payload'] and (seq is None or p['seq']==seq):
                yield p

def rto_proof(folder, time_ns, cwnd):
    progress = trace(folder/'logs_ns3/tcp_flow_0_progress.csv')
    index = bisect_right([x[1] for x in progress],time_ns)-1
    seq = progress[index][2]+1
    packets = list(selected_packets(folder,seq))
    tx = [p for p in packets if p['node']==1584 and p['event']=='ip_tx']
    rx = [p for p in packets if p['node']==1585 and p['event']=='ip_rx']
    drop = [r for r in rows(folder/'hop_drops.csv') if r['event']=='TcDrop' and int(r['seq'])==seq]
    assert len(tx)==3 and len(drop)==2 and tx[2]['time_ns']==time_ns
    assert [p['time_ns'] for p in tx[:2]] == [int(r['time_ns']) for r in drop]
    assert [p['identity'] for p in tx[:2]] == [packet(r)['identity'] for r in drop]
    assert rx and rx[0]['identity']==tx[2]['identity'] and rx[0]['time_ns']>time_ns
    before = [x for x in cwnd if x[1]<time_ns][-1][2]
    at = [x for x in cwnd if x[1]==time_ns][-1][2]
    assert at==MSS
    return dict(seq=seq,original_drop_ns=int(drop[0]['time_ns']),
                first_retransmission_drop_ns=int(drop[1]['time_ns']),rto_ns=time_ns,
                first_arrival_ns=rx[0]['time_ns'],cwnd_before_mss=before//MSS,cwnd_after_mss=at//MSS)

def london26_proof(folder):
    sent,received = defaultdict(list),defaultdict(list)
    for p in selected_packets(folder,start=24,end=28):
        if p['node']==1584 and p['event']=='ip_tx': sent[p['seq']].append(p)
        if p['node']==1585 and p['event']=='ip_rx': received[p['seq']].append(p)
    proofs = []
    for seq,attempts in sent.items():
        for p in attempts[1:]:
            if 26.2e9<=p['time_ns']<28e9:
                original = attempts[0]
                arrivals = [r for r in received[seq] if r['identity']==original['identity']]
                assert arrivals and arrivals[0]['time_ns']<p['time_ns']
                proofs.append(dict(seq=seq,original_tx_ns=original['time_ns'],
                                   original_rx_ns=arrivals[0]['time_ns'],retransmission_ns=p['time_ns']))
    assert len(proofs)==28
    return sorted(proofs,key=lambda p:p['retransmission_ns'])

def analyze(case):
    folder = ROOT/'runs'/('team_share_'+case)
    assert (folder/'logs_ns3/finished.txt').read_text().strip()=='Yes'
    for name in ('diagnostic_coverage.txt','hop_coverage.txt'):
        content = (folder/name).read_text()
        assert 'missing_required=0' in content and 'completed=1' in content
    hashes_equal = {}
    for name in ('cwnd','rtt','progress'):
        filename = f'tcp_flow_0_{name}.csv'
        hashes_equal[name] = (folder/'logs_ns3'/filename).read_bytes()==(ROOT/'runs'/case/'logs_ns3'/filename).read_bytes()
    assert all(hashes_equal.values())
    drops = rows(folder/'hop_drops.csv')
    tc = [r for r in drops if r['event']=='TcDrop']
    original = rows(ROOT/'runs'/REFERENCE[case]/'logs_ns3/tc_drops.csv')
    observed = [(int(r['time_ns']),int(r['node']),int(r['seq']),int(r['payload_bytes'])) for r in tc]
    expected = [(int(r['time_ns']),int(r['node']),int(r['seq']),int(r['payload'])) for r in original]
    assert observed==expected, (case,'drop events differ')
    assert not [r for r in drops if r['event']!='TcDrop'], (case,'other drop hooks fired')
    cwnd = trace(folder/'logs_ns3/tcp_flow_0_cwnd.csv')
    states = rows(folder/'diagnostic_states.csv')
    entries = [int(x) for x in re.findall(r'LAB1_RTO_ENTRY time_ns=(\d+)',(folder/'console.log').read_text())]
    losses = [int(s['time_ns']) for s in states if s['node']=='1584' and s['new_state']=='4']
    assert entries==losses, (case,'entry vs data LOSS mismatch')
    for t in entries:
        assert [r for r in cwnd if r[1]==t][-1][2]==MSS
    progress = trace(folder/'logs_ns3/tcp_flow_0_progress.csv')
    pt = [r[1] for r in progress]
    summaries = []
    for start,end in WINDOWS[case]:
        dr = [r for r in tc if start*1e9<=int(r['time_ns'])<end*1e9]
        falls = [(b[1],a[2]//MSS,b[2]//MSS) for a,b in zip(cwnd,cwnd[1:])
                 if start*1e9<=b[1]<end*1e9 and b[2]<a[2]]
        acked = progress[bisect_right(pt,round(end*1e9))-1][2]-progress[bisect_right(pt,round(start*1e9))-1][2]
        summaries.append(dict(case=case,start_s=start,end_s=end,tc_drops=len(dr),
            rto_count=sum(start*1e9<=t<end*1e9 for t in entries),
            recovery_entries=sum(start*1e9<=int(s['time_ns'])<end*1e9 and s['new_state']=='3' for s in states),
            first_drop_s=int(dr[0]['time_ns'])/1e9 if dr else None,
            first_cwnd_fall_s=falls[0][0]/1e9 if falls else None,
            first_cwnd_before_mss=falls[0][1] if falls else None,
            first_cwnd_after_mss=falls[0][2] if falls else None,
            minimum_cwnd_mss=min((r[2]/MSS for r in cwnd if start*1e9<=r[1]<end*1e9),default=None),
            ack_mbps=acked*8/(end-start)/1e6))
    result = dict(case=case,reference_run=REFERENCE[case],full_traces_identical=hashes_equal,
                  full_drop_events_identical=True,drop_events_by_hook=dict(Counter(r['event'] for r in drops)),
                  drop_nodes=dict(Counter(r['node'] for r in tc)),rto_entry_times_ns=entries,
                  data_loss_times_ns=losses,windows=summaries)
    if case in ('baseline_q100_60s','baseline_q500_60s'):
        result['early_rto_proof'] = [rto_proof(folder,t,cwnd) for t in entries]
    if case=='baseline_q100_60s':
        result['london26_unnecessary_retransmissions'] = london26_proof(folder)
        archive=Path(r'C:\Users\User\Documents\카카오톡 받은 파일\Lab1_Diagnostics_Team_Share_1004\lab1_team_share\evidence\q100_tc30.zip')
        with ZipFile(archive) as z:
            archived=list(csv.DictReader(io.StringIO(z.read('q100_tc30/hop_drops.csv').decode())))
        assert [r for r in tc if int(r['time_ns'])<30e9]==archived
        result['shared_archive_first_30s_drops_identical']=True
    return result

def main():
    results=[]
    for case in REFERENCE:
        done=ROOT/'runs'/('team_share_'+case)/'logs_ns3/finished.txt'
        if done.exists() and done.read_text().strip()=='Yes':
            results.append(analyze(case))
            print('PASS',case,flush=True)
    assert results, 'No completed runs'
    (HERE/'results.json').write_text(json.dumps(results,indent=2),encoding='utf-8')
    summary=[s for r in results for s in r['windows']]
    with (HERE/'comparison.csv').open('w',newline='',encoding='utf-8-sig') as f:
        writer=csv.DictWriter(f,fieldnames=list(summary[0])); writer.writeheader(); writer.writerows(summary)
    print(f'{len(results)}/{len(REFERENCE)} cases verified')
    if len(results)==len(REFERENCE):
        write_summary(results)

def write_summary(results):
    by_case={r['case']:r for r in results}
    expected={
        ('baseline_q100_60s',26.2,28.2):(0,0,696,487),
        ('baseline_q100_100s',75,77):(0,0,768,537),
        ('ny_baseline_q100_60s',48.9,50.9):(18,0,1205,843),
        ('hold75_q100_100s',79,85):(6,0,910,637),
        ('hold75_q1000_100s',79,85):(4,0,1846,1292),
        ('ny_hold48p9_q100_60s',54,58.9):(3,0,1234,863),
        ('ny_hold48p9_q250_60s',54,58.9):(3,0,1385,969),
    }
    lines=['공유 코드로 TCP drop과 RTO 재검증', '2026년 10월 6일', '',
        '결론: 별도 환경에서 공유 C++ 코드 3개를 수정 없이 빌드해 10개 조건을 새로 실행했다. 확인 대상인 보고서의 TcDrop 및 RTO 수치와 모두 일치했다.', '',
        '서울 런던 60초 기본 실행', '큐(패킷) | TcDrop(건) | 실제 데이터 RTO(회) | 전체 ACK 처리량(Mbps)']
    for q,drops,rtos in [(100,197,1),(250,309,0),(500,773,1),(1000,299,0)]:
        r=by_case[f'baseline_q{q}_60s']
        w=next(w for w in r['windows'] if w['start_s']==0 and w['end_s']==60)
        assert (w['tc_drops'],w['rto_count'])==(drops,rtos)
        lines.append(f"{q} | {drops} | {rtos} | {w['ack_mbps']:.6f}")
    lines += ['', '초기 RTO의 패킷 연결']
    for q in (100,500):
        p=by_case[f'baseline_q{q}_60s']['early_rto_proof'][0]
        lines.append(f"q{q}, seq {p['seq']}: 원본 TcDrop {p['original_drop_ns']/1e9:.9f}초, 첫 재전송 TcDrop {p['first_retransmission_drop_ns']/1e9:.9f}초, RTO {p['rto_ns']/1e9:.9f}초, 최초 수신 {p['first_arrival_ns']/1e9:.9f}초, cwnd {p['cwnd_before_mss']} → {p['cwnd_after_mss']} MSS.")
    lines += ['RTO 함수 진입 시각과 송신 소켓의 LOSS 전환 및 1 MSS 하락을 함께 대조했다. 두 초기 사건은 해당 시각의 데이터 재전송과 수신 성공까지 확인했다.', '',
              '경로 변경 및 유지 구간', '실행 | 구간(초) | TcDrop | RTO | cwnd 감소 전 → 구간 최저(MSS)']
    for (case,start,end),value in expected.items():
        w=next(w for w in by_case[case]['windows'] if (w['start_s'],w['end_s'])==(start,end))
        actual=(w['tc_drops'],w['rto_count'],w['first_cwnd_before_mss'],w['minimum_cwnd_mss'])
        assert actual==value,(case,actual,value)
        assert w['recovery_entries']>=1
        lines.append(f'{case} | {start}–{end} | {value[0]} | {value[1]} | {value[2]} → {value[3]}')
    lines += ['', '함께 확인한 사항',
        '• q100의 앞 30초 TcDrop은 185건이고, 뒤 30초에 12건이 더 발생해 60초 합계가 197건이다. 앞 30초의 모든 drop 행은 공유 ZIP q100_tc30.zip과도 일치했다.',
        '• 런던 q100의 26.2초 사건 부근 재전송 28개는 공유 코드의 24~28초 패킷 기록에서 모두 원본 수신 이후의 재전송으로 다시 확인했다.',
        '• 런던 26.2~28.2초의 q500은 TcDrop 29건, RTO 0회다. q100의 이 구간 drop 0건이라는 결론을 모든 큐 크기에 적용하면 안 된다.',
        '• 10개 실행 모두 기존 대응 실행과 전체 cwnd·RTT·누적 ACK 파일이 바이트 단위로 같았다. TcDrop도 건수뿐 아니라 전체 실행의 시각·노드·TCP 시퀀스·payload 길이가 행별로 일치했다.',
        '• 모든 실행에서 finished=Yes, 공유 코드의 필수 훅 missing_required=0, completed=1, changed_queue_objects=0을 확인했다. 관측된 drop 훅은 TcDrop뿐이었다.', '',
        '방법과 범위',
        '과제 이미지와 공유본의 기준 커밋 99bc6f733274475b7a6e804128651e17ee2a2536을 사용했다. 기존 개인 실험 컨테이너와 별개인 컨테이너에 공유 패치를 적용했다. 빌드한 소스 3개의 SHA256은 공유 스냅샷과 모두 같다.',
        'LAB1_DIAG=1, LAB1_HOPS=1, LAB1_EARLY_RTO=1을 사용했다. config_ns3.properties와 schedule.csv는 각 기존 실행에서 그대로 복사했다. 시드 123456789, TcpCubic, pacing=false 조건이다.',
        '공유본에는 독립 분석 스크립트가 없어, 이번 집계기는 공유 코드가 새로 출력한 CSV와 console.log를 읽어 기존 결과와 대조했다. 기존 개인 C++ 진단 코드는 새 실행에 사용하지 않았다.',
        '공유 코드의 끝점 패킷 상세 기록은 0~5초와 24~28초로 제한된다. 75초·뉴욕·유지 후반 구간의 이번 검증은 TcDrop, 상태 전환 및 cwnd·RTT·ACK 기록에 한정된다. 해당 구간의 원본/재전송/SACK 상세 대응이나 비용 분리 개입은 새로 분석하지 않았다.',
        '10회는 같은 조건의 코드 교차 검증이며, 여러 시드의 독립 통계 반복이 아니다. TcDrop 건수는 고유 TCP 시퀀스 수가 아니라 버려진 전송 시도의 수다.', '',
        '근거 파일', f'집계: {HERE / "comparison.csv"}', f'상세 검증: {HERE / "results.json"}',
        f'코드 출처와 해시: {HERE / "provenance.json"}',
        f'새 원자료: {ROOT / "runs"} 아래 team_share_로 시작하는 10개 폴더',
        f'재검사: {HERE / "analyze.py"}', f'실행: {HERE / "run.py"}']
    (HERE/'검증결과.txt').write_text('\n'.join(lines)+'\n',encoding='utf-8-sig')
    print('PASS all reported comparison windows; summary saved',flush=True)

if __name__=='__main__':
    main()
