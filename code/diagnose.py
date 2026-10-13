"""Generate packet-level evidence for the retained startup and route-change claims."""
from pathlib import Path
import json
import reproduce as r
ROOT=Path(__file__).resolve().parent

def main():
    a=r.module('diagnosis_analysis',ROOT/'v5_undo_hybrid/analyze.py')
    raw=r.module('diagnosis_packets',ROOT/'team_share_recheck/analyze.py')
    output={}
    for city in ['london','newyork']:
        folder=ROOT/'reproduced_baseline/experiment/runs'/f'{city}_baseline'
        if not folder.exists():continue
        trace=a.p.load(folder=folder)
        event=r.read(r.event_dir(city)/f'{city}_event.json')
        proof,summary=a.packet_proof(trace,event)
        drops=[x for x in trace['drops'] if x['event']=='TcDrop']
        item=dict(packet_evidence=proof,packet_summary=summary,
                  transition_metrics=a.p.interval(trace,event['nominal_s'],event['nominal_s']+2))
        if city=='london':
            item['startup_rto_proof']=[raw.rto_proof(folder,t,trace['raw']['cwnd']) for t in trace['rtos'] if t<5_000_000_000]
            item['tc_windows']=[dict(start_s=lo,end_s=hi,count=sum(lo*1e9<=int(x['time_ns'])<hi*1e9 for x in drops)) for lo,hi in [(0,5),(5,24),(24,26),(26,30),(0,30)]]
            item['drops_24_26']=[x for x in drops if 24e9<=int(x['time_ns'])<26e9]
            assert len(item['startup_rto_proof'])==1
            expected=dict(seq=666541,original_drop_ns=609036964,first_retransmission_drop_ns=720677290,rto_ns=1831725262)
            assert all(item['startup_rto_proof'][0][k]==v for k,v in expected.items())
            assert [x['count'] for x in item['tc_windows']]==[162,21,2,0,185]
        output[city]=item
        del trace
    out=ROOT/'generated/report';out.mkdir(parents=True,exist_ok=True)
    (out/'packet_diagnosis.json').write_text(json.dumps(output,indent=2)+'\n')
    print('PASS packet-level diagnosis for available baseline runs:',','.join(output),flush=True)
if __name__=='__main__':main()
