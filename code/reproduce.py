"""Replay the packaged v5/undo combinations without overwriting original evidence."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import csv
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parent
NS3 = Path('/home/ubuntu/ns-3.48')
OUT = ROOT / 'reproduced'
LATEST = ROOT / 'v5_undo_queueaware_20261011'
CITIES = ('london', 'newyork', 'sydney', 'singapore', 'losangeles', 'tokyo', 'manila')
ARMS = ('v5', 'undo', 'auto_watch_undo', 'guard_watch_undo', 'queue_guard_undo')
TRACE_FILES = ('logs_ns3/tcp_flow_0_cwnd.csv', 'logs_ns3/tcp_flow_0_rtt.csv',
               'logs_ns3/tcp_flow_0_progress.csv', 'diagnostic_last_rtt.csv', 'hop_drops.csv',
               'diagnostic_retransmissions.csv', 'diagnostic_states.csv',
               'diagnostic_packets.csv', 'handover.csv', 'controller.csv')


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def event_dir(city):
    assert city in CITIES
    return LATEST / 'manila' if city == 'manila' else LATEST


def reference(city, arm):
    assert city in CITIES and arm in ARMS
    if city == 'manila':
        folder = LATEST / 'manila'
    elif arm == 'queue_guard_undo':
        folder = LATEST
    elif city == 'tokyo':
        folder = ROOT / 'v5_undo_new_route_tokyo'
    elif arm in ('v5', 'undo'):
        folder = ROOT / 'v5_undo_hybrid'
    else:
        folder = ROOT / 'v5_undo_order_guard'
    return folder / 'runs' / f'{city}_{arm}'


def verify():
    manifest = read(ROOT / 'package_manifest.json')
    for rel, digest in manifest['files_sha256'].items():
        assert sha(ROOT / rel) == digest, rel
    module('candidate_analysis', ROOT / 'v5_undo_hybrid/analyze.py')
    module('candidate_runner', ROOT / 'v5_undo_hybrid/experiment.py')
    assert set(read(ROOT / 'reference_metrics.json')) == {f'{c}:{a}' for c in CITIES for a in ARMS}
    print('PASS candidate file hashes, runtime imports and 35 reference metric sets; no simulation performed', flush=True)


def build():
    import candidate_support
    candidate_support.build()


def prepare(cities):
    import candidate_support
    candidate_support.prepare(cities)


def run(cases):
    assert cases and len(cases) == len(set(cases)), 'Provide unique city:arm cases'
    parsed = [case.split(':') for case in cases]
    assert all(len(p) == 2 and p[0] in CITIES and p[1] in ARMS for p in parsed)
    built = read(OUT / 'build_provenance.json')
    experiment = OUT / 'experiment'
    experiment.mkdir(exist_ok=True)
    plan = dict(build=built, events={c: sha(event_dir(c) / f'{c}_event.txt') for c in CITIES},
                original_plan_sha256=sha(LATEST / 'frozen_plan.json'))
    frozen = experiment / 'frozen_plan.json'
    if frozen.exists():
        assert read(frozen) == plan, 'Rebuild differs from existing replay; use a fresh package extraction'
    else:
        frozen.write_text(json.dumps(plan, indent=2) + '\n')
    for city in CITIES:
        for ext in ('txt', 'json'):
            source = event_dir(city) / f'{city}_event.{ext}'
            target = experiment / source.name
            if target.exists():
                assert sha(target) == sha(source), target
            else:
                shutil.copyfile(source, target)
    prepare(sorted({p[0] for p in parsed}))
    exp = module('package_runner', ROOT / 'v5_undo_hybrid/experiment.py')
    exp.HERE = experiment
    exp.MODES = ARMS
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(exp.run, cases))


def analyze():
    a = module('package_analysis', ROOT / 'v5_undo_hybrid/analyze.py')
    folders = sorted((OUT / 'experiment/runs').glob('*'))
    assert folders, 'Run at least one case first'
    built = read(OUT / 'build_provenance.json')
    original_hashes = read(ROOT / 'original_file_hashes.json')['files_sha256']
    original_metrics = read(ROOT / 'reference_metrics.json')
    metrics, details = [], []
    for folder in folders:
        manifest = read(folder / 'manifest.json')
        city, arm = manifest['city'], manifest['arm']
        assert manifest['exit_code'] == 0 and manifest['build'] == built
        event = read(event_dir(city) / f'{city}_event.json')
        assert manifest['event_sha256'] == sha(event_dir(city) / f'{city}_event.txt')
        prior_folder = reference(city, arm)
        for name, key in [('config_ns3.properties', 'config_sha256'), ('schedule.csv', 'schedule_sha256')]:
            assert sha(folder / name) == manifest[key] == sha(prior_folder / name)
        # Saved hashes preserve exact trace checks without shipping the large original logs.
        rel = prior_folder.relative_to(ROOT).as_posix()
        for name in TRACE_FILES:
            assert sha(folder / name) == original_hashes[f'{rel}/{name}'], (city, arm, name)
        trace = a.p.load(folder=folder)
        control = a.v5.controller(trace, 'baseline' if arm == 'undo' else 'adaptive', event, 100)
        proof, _ = a.packet_proof(trace, event)
        undo = a.undo_checks(trace, arm, event, proof)
        for window, start, stop in [('event2', event['nominal_s'], event['nominal_s'] + 2),
                                    ('event10', event['nominal_s'], event['stop_s']),
                                    ('whole', 0, event['stop_s'])]:
            current = a.p.interval(trace, start, stop)
            assert current == original_metrics[f'{city}:{arm}'][window], (city, arm, window)
            metrics.append(dict(city=city, arm=arm, window=window, **current))
        details.append(dict(city=city, arm=arm, **control, undo=undo, matches_original=True))
        print('PASS exact original transport trace (SHA-256) and metrics:', city, arm, flush=True)
    (OUT / 'results.json').write_text(json.dumps(dict(metrics=metrics, details=details), indent=2) + '\n')
    with (OUT / 'comparison.csv').open('w', encoding='utf-8-sig', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(metrics[0]))
        writer.writeheader()
        writer.writerows(metrics)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('verify', 'build', 'run', 'analyze'))
    parser.add_argument('cases', nargs='*', help='city:arm (run only)')
    args = parser.parse_args()
    if args.action == 'run':
        run(args.cases)
    else:
        assert not args.cases, 'Cases are only accepted by run'
        globals()[args.action]()
