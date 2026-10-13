"""Fresh-state preparation and clean-tree patching for the submission candidate."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import reproduce as r

ROOT = Path(__file__).resolve().parent
GENERATED = ROOT / 'generated'

def record(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + '\n')

def check_state(folder, reference):
    for rel, digest in reference['files_sha256'].items():
        p = folder / rel
        if not p.is_file() or r.sha(p) != digest:
            raise RuntimeError('Generated state differs from historical simulator input: ' + str(p))


def match_full_snapshot_encoding(folder, reference, audit_path):
    """Match historical full-reset snapshots using only freshly generated deltas.

    Never change routing values or expected hashes. Refuse every other mismatch.
    """
    table = {}
    records = []
    files = sorted(folder.glob('dynamic_state_*/fstate_*.txt'),
                   key=lambda p: int(p.stem.split('_')[1]))
    for path in files:
        for line in path.read_text().splitlines():
            fields = tuple(map(int, line.split(',')))
            assert len(fields) == 5
            table[fields[:2]] = fields[2:]
        rel = path.relative_to(folder).as_posix()
        expected = reference['files_sha256'][rel]
        original = r.sha(path)
        if original == expected:
            continue
        full = ''.join(','.join(map(str, key + table[key])) + '\n'
                       for key in sorted(table)).encode()
        digest = hashlib.sha256(full).hexdigest()
        if digest != expected:
            raise RuntimeError('Generated routing values differ; no encoding repair: ' + str(path))
        decoded = {}
        for line in full.decode().splitlines():
            fields = tuple(map(int, line.split(',')))
            decoded[fields[:2]] = fields[2:]
        assert decoded == table, 'Encoding repair must preserve the complete routing table'
        backup = audit_path.parent / 'original_delta_encoding' / rel
        backup.parent.mkdir(parents=True, exist_ok=True)
        if backup.exists():
            raise RuntimeError('Preserving previous encoding evidence: ' + str(backup))
        shutil.copyfile(path, backup)
        path.write_bytes(full)
        records.append(dict(file=rel,original_delta_sha256=original,
                            full_snapshot_sha256=digest,rows=len(table),
                            routing_table_unchanged=True))
    record(audit_path, records)
    print('PASS exact historical snapshot encoding; unchanged routing tables:', len(records), flush=True)

def prepare(cities):
    refs = r.read(ROOT / 'state_reference.json')
    for city in cities:
        if city not in r.CITIES:
            raise ValueError(city)
        spec = refs[city]
        generated_root = GENERATED / 'states' / city
        receipt = generated_root / 'generation_receipt.json'
        state = generated_root / 'state'
        if not receipt.exists():
            if generated_root.exists():
                raise RuntimeError('Incomplete generation preserved; inspect and move this folder before retry: ' + str(generated_root))
            generated_root.mkdir(parents=True)
            lab = Path(os.environ['LAB'])
            env = dict(os.environ, SATGENPY=os.environ.get('SATGENPY', str(lab.parent / 'hypatia/satgenpy')))
            if not Path(env['SATGENPY']).is_dir():
                raise RuntimeError('Course Hypatia dependency not found: ' + env['SATGENPY'])
            command = [sys.executable, str(ROOT / 'adaptive_handover_v5/gen_state_reference.py'),
                       str(generated_root), '--duration', '200', '--step-ms', '100', '--threads', '1']
            for station in spec['stations']:
                command += ['--gs', station]
            print('GENERATE state', city, '(200 s, 100 ms; runtime not yet measured)', flush=True)
            start = time.monotonic()
            with (generated_root / 'generation.log').open('w') as stream:
                subprocess.run(command, env=env, stdout=stream, stderr=subprocess.STDOUT, check=True)
            match_full_snapshot_encoding(state, spec, generated_root / 'snapshot_encoding_receipt.json')
            check_state(state, spec)
            record(receipt, dict(command=command, generator_sha256=r.sha(ROOT / 'adaptive_handover_v5/gen_state_reference.py'),
                   reference_sha256=r.sha(ROOT / 'state_reference.json'), wall_seconds=time.monotonic()-start,
                   verified_simulator_files=len(spec['files_sha256'])))
        else:
            saved = r.read(receipt)
            assert saved['generator_sha256'] == r.sha(ROOT / 'adaptive_handover_v5/gen_state_reference.py')
            assert saved['reference_sha256'] == r.sha(ROOT / 'state_reference.json')
            check_state(state, spec)
        # Keep original absolute paths so reference config/trace comparisons remain exact.
        # A preinstalled London example is checked before any files are copied.
        target = Path(r.read(r.event_dir(city) / f'{city}_event.json')['native_state'])
        for rel, digest in spec['files_sha256'].items():
            p = target / rel
            if p.exists() and (not p.is_file() or r.sha(p) != digest):
                raise RuntimeError('Existing state differs; preserved without overwrite: ' + str(p))
        for rel in spec['files_sha256']:
            p = target / rel
            if not p.exists():
                p.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(state / rel, p)
        check_state(target, spec)
        print('PASS generated state and installed simulator inputs:', city, len(spec['files_sha256']), 'file hashes', flush=True)

def check_sources(expected):
    for rel, digest in expected.items():
        if not (r.NS3 / rel).is_file() or r.sha(r.NS3 / rel) != digest:
            raise RuntimeError('Source mismatch: ' + rel)

def export_course_patch():
    expected = r.read(r.LATEST / 'frozen_plan.json')['build']['sources']
    check_sources(expected)
    tool = shutil.which('make_patch.sh') or str(Path(os.environ['LAB']) / 'scripts/make_patch.sh')
    if not Path(tool).is_file():
        raise RuntimeError('Required course make_patch.sh is unavailable')
    output = Path('/work/ns3.patch')
    # This is a fresh candidate workspace; avoid replacing unrelated user patches.
    if output.exists():
        raise RuntimeError('Preserving existing /work/ns3.patch. Move it before course patch export.')
    subprocess.run(['bash', tool], cwd=r.NS3, check=True)
    if not output.is_file() or not output.stat().st_size:
        raise RuntimeError('Course tool did not produce /work/ns3.patch')
    names = subprocess.check_output(['git', 'apply', '--numstat', str(output)], cwd=r.NS3, text=True)
    actual = {line.split('\t', 2)[2] for line in names.splitlines()}
    if actual != set(expected):
        raise RuntimeError('Export includes missing/unrelated paths; inspect /work/ns3.patch: ' + repr(actual))
    subprocess.run(['git', 'apply', '--reverse', '--check', str(output)], cwd=r.NS3, check=True)
    dest = GENERATED / 'course_export/ns3.patch'
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(output, dest)
    record(dest.with_suffix('.json'), dict(tool=tool, sha256=r.sha(dest), files=sorted(actual),
           validation='reverse apply check against exact final sources; forward clean-volume test remains required'))
    print('PASS make_patch.sh export:', dest, flush=True)

def build():
    expected = r.read(r.LATEST / 'frozen_plan.json')['build']['sources']
    base = r.read(ROOT / 'base_source_manifest.json')
    complete = all((r.NS3 / p).is_file() and r.sha(r.NS3 / p) == h for p,h in expected.items())
    if not complete:
        status = subprocess.check_output(['git', 'status', '--porcelain'], cwd=r.NS3, text=True)
        if status.strip():
            raise RuntimeError('Use a fresh course volume; ns-3 tree contains existing edits')
        for rel, digest in base.items():
            p = r.NS3 / rel
            if digest is None:
                assert not p.exists(), rel
            else:
                assert p.is_file() and r.sha(p) == digest, 'Course base differs: ' + rel
        subprocess.run(['git', 'apply', '--check', str(ROOT / 'ns3.patch')], cwd=r.NS3, check=True)
        subprocess.run(['git', 'apply', str(ROOT / 'ns3.patch')], cwd=r.NS3, check=True)
    check_sources(expected)
    r.OUT.mkdir(exist_ok=True)
    with (r.OUT / 'build.log').open('w') as stream:
        subprocess.run(['cmake', '--build', 'cmake-cache', '--target', 'scratch_main_satnet_main_satnet', '-j2'],
                       cwd=r.NS3, stdout=stream, stderr=subprocess.STDOUT, check=True)
    result = dict(sources=expected, binary_sha256=r.sha(r.NS3/'build/scratch/main_satnet/ns3.48-main_satnet'),
                  internet_sha256=r.sha(r.NS3/'build/lib/libns3.48-internet.so'))
    old = r.OUT / 'build_provenance.json'
    if old.exists() and r.read(old) != result:
        raise RuntimeError('Build provenance changed; existing evidence preserved, use a fresh output tree')
    record(old, result)
    print('PASS candidate patch built; local binary hashes recorded', flush=True)

if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=['states', 'export-patch'])
    p.add_argument('cities', nargs='*', help='City names; omit for all seven')
    args = p.parse_args()
    if args.action == 'states':
        prepare(args.cities or list(r.CITIES))
    else:
        if args.cities: p.error('No cities accepted for export-patch')
        export_course_patch()
