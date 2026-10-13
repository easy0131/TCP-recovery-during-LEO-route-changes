#!/usr/bin/env python3
"""Recompute ACK rate and time-weighted SRTT from declared ZIP inputs.
Python 3 standard library for statistics; matplotlib is optional for figures.
"""
import argparse, bisect, csv, hashlib, io, json, zipfile
from pathlib import Path

def read_series(z, path):
    rows = [tuple(map(int,r)) for r in csv.reader(io.StringIO(z.read(path).decode())) if r]
    if not rows or any(len(r)!=3 or r[0]!=0 for r in rows):
        raise ValueError('Expected nonempty flow 0 series: '+path)
    if any(b[1]<a[1] for a,b in zip(rows,rows[1:])): raise ValueError('Unsorted time: '+path)
    return [(r[1],r[2]) for r in rows]

def held(series, t):
    i=bisect.bisect_right([r[0] for r in series],t)-1
    if i<0: raise ValueError('No observation at boundary')
    return series[i][1]

def distribution(series, lo, hi):
    # Right-continuous held value; equal-time earlier rows have zero duration.
    weighted=[(v,max(0,min(end,hi)-max(start,lo))) for (start,v),(end,_) in zip(series,series[1:])]
    weighted=sorted((v,w) for v,w in weighted if w>0)
    total=sum(w for v,w in weighted)
    if not total: raise ValueError('No SRTT coverage')
    quantiles=[]
    for q in (.5,.95):
        cumulative=0
        for v,w in weighted:
            cumulative+=w
            if cumulative>=q*total:
                quantiles.append(v/1e6);break
    return total/1e9,sum(v*w for v,w in weighted)/total/1e6,*quantiles

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--manifest',type=Path,default=Path(__file__).resolve().parents[1]/'analysis/manifest.json');ap.add_argument('--out',type=Path);ap.add_argument('--no-plots',action='store_true');args=ap.parse_args()
    manifest=json.loads(args.manifest.read_text());root=args.manifest.parent.parent;out=args.out or root/'analysis/generated';out.mkdir(parents=True,exist_ok=True)
    result=[];data={};provenance=[];reference=None
    for item in manifest['runs']:
        archive=root/item['archive'];run=item['run'];pre='runs/'+run+'/'
        with zipfile.ZipFile(archive) as z:
            if z.read(pre+'logs_ns3/finished.txt').decode().strip()!='Yes':raise ValueError('Incomplete '+run)
            cfg=dict(line.split('=',1) for line in z.read(pre+'config_ns3.properties').decode().splitlines() if '=' in line and not line.startswith('#'))
            for key in ('isl_max_queue_size_pkts','gsl_max_queue_size_pkts'):
                if int(cfg[key])!=item['queue']:raise ValueError('Queue mismatch')
            common={k:v for k,v in cfg.items() if k not in ('isl_max_queue_size_pkts','gsl_max_queue_size_pkts')}
            if reference is None:reference=common
            elif common!=reference:raise ValueError('Configurations differ beyond queue sizes')
            p=read_series(z,pre+'logs_ns3/tcp_flow_0_progress.csv');r=read_series(z,pre+'logs_ns3/tcp_flow_0_rtt.csv');c=read_series(z,pre+'logs_ns3/tcp_flow_0_cwnd.csv')
            if any(b[1]<a[1] for a,b in zip(p,p[1:])):raise ValueError('Nonmonotonic ACK bytes')
            end=int(cfg['simulation_end_time_ns'])
            if p[-1][0]!=end or r[-1][0]!=end:raise ValueError('Missing final sample')
            flow=next(csv.reader(io.StringIO(z.read(pre+'logs_ns3/tcp_flows.csv').decode())))
            if int(flow[7])!=p[-1][1]:raise ValueError('Final byte mismatch')
            data[item['queue']]=(p,r,c)
            provenance.append({'queue':item['queue'],'run':run,'archive':item['archive'],'sha256':hashlib.sha256(archive.read_bytes()).hexdigest(),'progress_rows':len(p),'srtt_rows':len(r),'final_acked_bytes':p[-1][1],'first_srtt_ns':r[0][0]})
            for lo,hi in manifest['windows_s']:
                l,h=round(lo*1e9),round(hi*1e9);coverage,mean,p50,p95=distribution(r,l,h)
                result.append(dict(queue=item['queue'],start_s=lo,end_s=hi,acked_bytes=held(p,h)-held(p,l),ack_mbps=(held(p,h)-held(p,l))*8/(hi-lo)/1e6,srtt_coverage_s=coverage,srtt_mean_ms=mean,srtt_p50_ms=p50,srtt_p95_ms=p95))
    with (out/'queue_summary.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(result[0]));w.writeheader();w.writerows(result)
    (out/'results.json').write_text(json.dumps({'method':'ACK bytes at latest timestamp <= boundary; duration weighted held SRTT; weighted inverse CDF quantiles','runs':provenance,'results':result},ensure_ascii=False,indent=2))
    if not args.no_plots:
        import matplotlib;matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        colors={100:'#b84a48',250:'#22846d',500:'#3678b2',1000:'#8764a4'}
        fig,axs=plt.subplots(3,1,figsize=(9,8),sharex=True,layout='constrained')
        for q,(p,r,c) in data.items():
            grid=[i*10_000_000 for i in range(6001)]
            def sample(s):
                ts=[a for a,b in s];return [s[i][1] if (i:=bisect.bisect_right(ts,t)-1)>=0 else float('nan') for t in grid]
            axs[0].plot([t/1e9 for t in grid],[v/1380 for v in sample(c)],label=f'q{q}',color=colors[q],lw=1)
            axs[1].plot([t/1e9 for t in grid],[v/1e6 for v in sample(r)],color=colors[q],lw=1)
            edges=[i*500_000_000 for i in range(121)];vals=[held(p,t) for t in edges]
            axs[2].stairs([(b-a)*8/.5/1e6 for a,b in zip(vals,vals[1:])],[t/1e9 for t in edges],color=colors[q],lw=1.2)
        for ax,lab in zip(axs,['cwnd (MSS)','SRTT (ms)','ACK rate (Mbps)']):ax.set_ylabel(lab);ax.grid(alpha=.2);ax.axvline(26.2,color='gray',ls=':',lw=1)
        axs[0].legend(ncol=4);axs[2].set_xlabel('Simulation time (s)');fig.savefig(out/'queue_timeseries.png',dpi=180);plt.close(fig)
        fig,axs=plt.subplots(1,2,figsize=(9,3.5),layout='constrained')
        for ax,(lo,hi) in zip(axs,[(0,60),(20,60)]):
            for row in result:
                if (row['start_s'],row['end_s'])==(lo,hi):
                    ax.scatter(row['srtt_p50_ms'],row['ack_mbps'],color=colors[row['queue']],s=45);ax.annotate('q'+str(row['queue']),(row['srtt_p50_ms'],row['ack_mbps']),xytext=(5,6),textcoords='offset points',fontsize=9)
            ax.set_title(f'{lo}-{hi} s');ax.set_xlabel('Time-weighted median SRTT (ms)');ax.set_ylabel('ACK rate (Mbps)');ax.set_xlim(85,200);ax.set_ylim(60,101);ax.grid(alpha=.2)
        fig.savefig(out/'queue_tradeoff.png',dpi=180);plt.close(fig)
        fig,ax=plt.subplots(figsize=(8,3.6),layout='constrained')
        for q,(_,r,_) in data.items():
            weighted=sorted((v/1e6,e-t) for (t,v),(e,_) in zip(r,r[1:]) if e>t);total=sum(w for v,w in weighted);cum=0;xs=[];ys=[]
            for v,w in weighted:cum+=w;xs.append(v);ys.append(cum/total)
            ax.plot(xs,ys,label=f'q{q}',color=colors[q])
        ax.set_xlabel('SRTT (ms)');ax.set_ylabel('Fraction of observed time');ax.set_title('Held SRTT distribution, first observation to 60 s');ax.legend(ncol=4);ax.grid(alpha=.2);fig.savefig(out/'srtt_cdf.png',dpi=180);plt.close(fig)
    print('Wrote',len(result),'rows to',out)
if __name__=='__main__':main()
