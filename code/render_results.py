"""Regenerate report tables and plots using current, locally replayed results only."""
import csv
import json
from pathlib import Path
import reproduce as r
ROOT=Path(__file__).resolve().parent

def save_csv(path, rows):
    with path.open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)

def main():
    out=ROOT/'generated/report';out.mkdir(parents=True,exist_ok=True)
    base=r.read(ROOT/'reproduced_baseline/results.json')
    replay=r.read(ROOT/'reproduced/results.json')
    old=r.read(ROOT/'baseline_reference.json')
    prior={(x['city'],x['window']):x for x in old['metrics']}
    for x in base['metrics']:
        assert x==prior[x['city'],x['window']], ('Baseline metrics differ from 2026-10-12 run',x['city'],x['window'])
    # r.analyze checked exact improvement metrics; baseline equality is added here.
    rows=base['metrics']+replay['metrics']
    selected={(x['city'],x['arm'],x['window']):x for x in rows}
    comparisons=[]
    table=['| Route | Basic TCP | v5 | CUBIC-only undo | Latest combination | Latest gain |',
           '|---|---:|---:|---:|---:|---:|']
    for city in r.CITIES:
        b=selected.get((city,'baseline','event10'))
        if b is None: continue
        values=[]
        for arm in ['baseline','v5','undo','queue_guard_undo']:
            cur=selected.get((city,arm,'event10'))
            values.append('not replayed' if cur is None else f"{cur['ack_mbps']:.3f}")
            if cur is None: continue
            gain=100*(cur['ack_mbps']/b['ack_mbps']-1)
            small=selected[city,arm,'event2']
            comparisons.append(dict(city=city,arm=arm,event10_ack_mbps=cur['ack_mbps'],gain_pct=gain,
                                    whole_end_s=selected[city,arm,'whole']['end_s'],
                                    whole_ack_gain_pct=100*(selected[city,arm,'whole']['ack_mbps']/selected[city,'baseline','whole']['ack_mbps']-1),
                                    event10_retransmissions=cur['retransmissions'],event10_tc_drops=cur['tc_drops'],
                                    event2_last_rtt_p95_ms=small['last_rtt_p95_ms'],event2_srtt_p95_ms=small['rtt_p95_ms']))
        latest=selected.get((city,'queue_guard_undo','event10'))
        gain='not replayed' if latest is None else f"{100*(latest['ack_mbps']/b['ack_mbps']-1):+.2f}%"
        table.append('| '+' | '.join([city,*values,gain])+' |')
    (out/'route_table.md').write_text('ACK rate in Mbps; [nominal transition, nominal + 10 s]. Gains use the same-route baseline.\n\n'+'\n'.join(table)+'\n')
    save_csv(out/'route_comparison.csv',comparisons)
    details={}
    for d in replay['details']:
        if d['arm']=='queue_guard_undo': details[d['city']]=d
    decisions=[]
    for city,d in details.items():
        cur=selected[city,'queue_guard_undo','event2']
        refs=[selected.get((city,a,'event2')) for a in ['v5','auto_watch_undo']]
        limit=min(x['last_rtt_p95_ms'] for x in refs)*1.1 if all(x is not None for x in refs) else None
        decisions.append(dict(city=city,latest_event2_last_rtt_p95_ms=cur['last_rtt_p95_ms'],
           baseline_event2_last_rtt_p95_ms=selected[city,'baseline','event2']['last_rtt_p95_ms'],
           baseline_relative_delay_pct=100*(cur['last_rtt_p95_ms']/selected[city,'baseline','event2']['last_rtt_p95_ms']-1),
           baseline_relative_10pct_limit_ms=1.1*selected[city,'baseline','event2']['last_rtt_p95_ms'],
           diagnostic_delay_limit_ms=limit,delay_pass=None if limit is None else cur['last_rtt_p95_ms']<=limit,
           gate_drops=d['gate_drops'],undo_apply_count=len(d['undo']['apply']),
           note='Delay check only; not an independent held-out success or a full acceptance verdict.'))
    (out/'latest_diagnostics.json').write_text(json.dumps(decisions,indent=2)+'\n')
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    arms=['baseline','v5','undo','queue_guard_undo']
    names=['Basic TCP','v5','CUBIC-only undo','Latest combination']
    cities=[c for c in r.CITIES if all((c,a,'event10') in selected for a in arms)]
    if cities:
        fig,ax=plt.subplots(figsize=(7,3),layout='constrained')
        for j,(arm,label) in enumerate(zip(arms,names)):
            ax.bar([i+(j-1.5)*.19 for i in range(len(cities))],[selected[c,arm,'event10']['ack_mbps'] for c in cities],width=.19,label=label)
        ax.set_xticks(range(len(cities)),[c.title() for c in cities],rotation=20)
        ax.set_ylabel('ACK rate (Mbps)');ax.set_ylim(0,105);ax.legend(fontsize=7,ncol=2);ax.grid(axis='y',alpha=.2)
        fig.savefig(out/'route_ack_rate.pdf');fig.savefig(out/'route_ack_rate.png',dpi=180);plt.close(fig)
    # These curves are read from fresh logs; metrics references cannot stand in for traces.
    folders=[ROOT/'reproduced_baseline/experiment/runs/london_baseline',ROOT/'reproduced/experiment/runs/london_queue_guard_undo']
    if all((p/'logs_ns3/tcp_flow_0_cwnd.csv').is_file() for p in folders):
        fig,axes=plt.subplots(2,1,figsize=(6.5,4),sharex=True,layout='constrained')
        for folder,label in zip(folders,['Basic TCP','Latest combination']):
            for ax,key,divisor in zip(axes,['cwnd','rtt'],[1380,1e6]):
                with (folder/f'logs_ns3/tcp_flow_0_{key}.csv').open() as f:
                    points=[(int(row[1])/1e9,int(row[2])/divisor) for row in csv.reader(f) if row]
                # Preserve the held value entering the displayed interval.
                before=[p for p in points if p[0]<24];visible=([before[-1]] if before else [])+[p for p in points if 24<=p[0]<=31]
                ax.step([p[0] for p in visible],[p[1] for p in visible],where='post',label=label)
        for ax in axes:ax.axvline(26.2,color='gray',linestyle='--',linewidth=.8);ax.grid(alpha=.2);ax.set_xlim(24,31)
        axes[0].set_ylabel('Congestion window (MSS)');axes[0].legend(fontsize=8)
        axes[1].set_ylabel('SRTT (ms)');axes[1].set_xlabel('Simulation time (s)')
        fig.savefig(out/'london_transition.pdf');fig.savefig(out/'london_transition.png',dpi=180);plt.close(fig)
    print('PASS report tables/plots from available local replays; baseline metric equality checked',flush=True)
if __name__=='__main__':main()
