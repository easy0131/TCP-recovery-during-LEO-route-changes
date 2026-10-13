"""Add baseline runs to the unchanged 20261011 Lite package; no C++ rebuild."""
import argparse
import csv
import importlib.util
import json
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parent
BASE_OUT = ROOT / 'reproduced_baseline'
REPLAY_OUT = ROOT / 'reproduced'


def original():
    path = ROOT / 'reproduce.py'
    if not path.is_file():
        raise SystemExit('Place reproduce_baseline.py beside the original reproduce.py')
    spec = importlib.util.spec_from_file_location('baseline_original_runner', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')


def select_cities(r, cities):
    cities = list(r.CITIES) if not cities else cities
    if len(cities) != len(set(cities)) or any(c not in r.CITIES for c in cities):
        raise SystemExit('Supply unique cities: ' + ' '.join(r.CITIES))
    return cities


def run(r, cities):
    cities = select_cities(r, cities)
    built = r.read(REPLAY_OUT / 'build_provenance.json')
    # Fail before launching any member of a batch if output already exists.
    for city in cities:
        dest = BASE_OUT / 'experiment/runs' / (city + '_baseline')
        if dest.exists():
            raise SystemExit('Existing evidence: ' + str(dest) + '; run only remaining cities')
    BASE_OUT.mkdir(exist_ok=True)
    target = BASE_OUT / 'build_provenance.json'
    if target.exists():
        assert r.read(target) == built, 'Build differs from saved baseline evidence'
    else:
        shutil.copyfile(REPLAY_OUT / 'build_provenance.json', target)
    r.OUT = BASE_OUT
    r.ARMS = ('baseline',)
    r.run([city + ':baseline' for city in cities])


def csv_write(path, rows):
    if not rows:
        return
    with path.open('w', newline='', encoding='utf-8-sig') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def analyze(r):
    folders = sorted((BASE_OUT / 'experiment/runs').glob('*_baseline'))
    if not folders:
        raise SystemExit('Run a baseline case first')
    built = r.read(BASE_OUT / 'build_provenance.json')
    assert built == r.read(REPLAY_OUT / 'build_provenance.json')
    # Preserve the original replay checks. A failed reference check stops comparison.
    replay_folders = list((REPLAY_OUT / 'experiment/runs').glob('*'))
    if replay_folders:
        r.analyze()
    a = r.module('baseline_analysis', ROOT / 'v5_undo_hybrid/analyze.py')
    metrics, details, comparisons = [], [], []
    replay = r.read(REPLAY_OUT / 'results.json') if replay_folders else {'metrics': []}
    for folder in folders:
        manifest = r.read(folder / 'manifest.json')
        city = manifest['city']
        assert city in r.CITIES and manifest['arm'] == 'baseline'
        assert manifest['exit_code'] == 0 and manifest['build'] == built
        assert (folder / 'logs_ns3/finished.txt').read_text().strip() == 'Yes'
        event = r.read(r.event_dir(city) / f'{city}_event.json')
        assert manifest['event_sha256'] == r.sha(r.event_dir(city) / f'{city}_event.txt')
        env = manifest['environment']
        assert env['HYBRID_ARM'] == env['ADAPT_MODE'] == 'baseline'
        assert env['HYBRID_FULL_UNDO'] == '0'
        # Every control arm uses these same configuration and schedule bytes.
        prior = r.reference(city, 'undo')
        for filename, key in [('config_ns3.properties', 'config_sha256'), ('schedule.csv', 'schedule_sha256')]:
            assert r.sha(folder / filename) == manifest[key] == r.sha(prior / filename)
        trace = a.p.load(folder=folder)
        assert trace['data']['progress'][0][-1] == round(event['stop_s'] * 1e9)
        control = a.v5.controller(trace, 'baseline', event, 100)
        proof, _ = a.packet_proof(trace, event)
        undo = a.undo_checks(trace, 'baseline', event, proof)
        assert control['actual_start_s'] is None and not control['pacing_used']
        assert not control['gate_drops'] and all(g['admitted'] == 0 for g in control['gates'])
        assert not any(undo[k] for k in ('arm', 'begin', 'apply', 'reject', 'windows'))
        baseline_metrics = {}
        for window, start, stop in [('event2', event['nominal_s'], event['nominal_s'] + 2),
                                    ('event10', event['nominal_s'], event['stop_s']),
                                    ('whole', 0, event['stop_s'])]:
            row = dict(city=city, arm='baseline', window=window, **a.p.interval(trace, start, stop))
            metrics.append(row)
            baseline_metrics[window] = row
        detail = dict(city=city, arm='baseline', **control, undo=undo,
                      verification='new baseline; controls disabled; no original hash target',
                      trace_sha256={name: r.sha(folder / name) for name in r.TRACE_FILES}, paired_arms=[])
        for arm in r.ARMS:
            paired = REPLAY_OUT / 'experiment/runs' / f'{city}_{arm}'
            if not paired.exists():
                continue
            for filename in ('config_ns3.properties', 'schedule.csv'):
                assert (folder / filename).read_bytes() == (paired / filename).read_bytes()
            other = a.p.load(folder=paired)
            # Controls have not started at first_check_ns; prefixes must match exactly.
            a.v5.v1.same_prefix(trace, other, event['first_check_ns'])
            del other
            detail['paired_arms'].append(arm)
            rows = {x['window']: x for x in replay['metrics'] if x['city'] == city and x['arm'] == arm}
            base_rate = baseline_metrics['event10']['ack_mbps']
            comparisons.append(dict(city=city, arm=arm, baseline_ack_mbps=base_rate,
                arm_ack_mbps=rows['event10']['ack_mbps'],
                gain_pct=(rows['event10']['ack_mbps'] / base_rate - 1) * 100 if base_rate else None,
                baseline_event2_last_rtt_p95_ms=baseline_metrics['event2']['last_rtt_p95_ms'],
                arm_event2_last_rtt_p95_ms=rows['event2']['last_rtt_p95_ms'],
                baseline_event10_retransmissions=baseline_metrics['event10']['retransmissions'],
                arm_event10_retransmissions=rows['event10']['retransmissions']))
        details.append(detail)
        print('PASS new baseline controls/configuration:', city, '; paired:', ','.join(detail['paired_arms']) or 'none', flush=True)
    write_json(BASE_OUT / 'results.json', dict(metrics=metrics, details=details, comparisons=comparisons))
    csv_write(BASE_OUT / 'comparison.csv', metrics)
    csv_write(BASE_OUT / 'paired_comparison.csv', comparisons)
    csv_write(BASE_OUT / 'all_replayed_metrics.csv', metrics + replay['metrics'])
    print('SAVED reproduced_baseline: baseline metrics and locally replayed paired comparisons', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('verify', 'run', 'analyze'))
    parser.add_argument('cities', nargs='*')
    args = parser.parse_args()
    r = original()
    if args.action == 'run':
        run(r, args.cities)
    else:
        if args.cities:
            parser.error('City arguments are accepted only by run')
        if args.action == 'verify':
            r.verify()
            print('PASS baseline extension imports; original package unchanged. Simulation not performed.', flush=True)
        else:
            analyze(r)


if __name__ == '__main__':
    main()
