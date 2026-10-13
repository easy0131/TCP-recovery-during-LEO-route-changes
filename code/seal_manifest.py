"""Accept only a verified course-tool patch export; preserve scientific references."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
from zipfile import ZipFile, ZIP_DEFLATED
import reproduce as r
ROOT=Path(__file__).resolve().parent

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--accept-course-patch',action='store_true',required=True);p.parse_args()
    manifest=r.read(ROOT/'package_manifest.json');export=ROOT/'generated/course_export/ns3.patch'
    receipt=r.read(export.with_suffix('.json'))
    assert receipt['sha256']==r.sha(export)
    expected=r.read(r.LATEST/'frozen_plan.json')['build']['sources']
    assert set(receipt['files'])==set(expected)
    for rel,digest in manifest['files_sha256'].items():
        assert r.sha(ROOT/rel)==digest, 'Existing source changed; do not silently reseal: '+rel
    for rel,digest in expected.items():assert r.sha(r.NS3/rel)==digest, rel
    subprocess.run(['git','apply','--reverse','--check',str(export)],cwd=r.NS3,check=True)
    names=subprocess.check_output(['git','apply','--numstat',str(export)],cwd=r.NS3,text=True)
    assert {x.split('\t',2)[2] for x in names.splitlines()}==set(expected)
    previous=r.sha(ROOT/'ns3.patch')
    shutil.copyfile(export,ROOT/'ns3.patch')
    audit=ROOT/'course_patch_provenance.json'
    audit.write_text(json.dumps(dict(previous_patch_sha256=previous,course_export=receipt,
                                   note='This receipt does not certify simulations or a second clean-volume build.'),indent=2)+'\n')
    manifest['files_sha256']['ns3.patch']=r.sha(ROOT/'ns3.patch')
    manifest['files_sha256']['course_patch_provenance.json']=r.sha(audit)
    (ROOT/'package_manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    r.verify()
    dest=ROOT/'generated/submission_code.zip'
    with ZipFile(dest,'w',ZIP_DEFLATED) as z:
        for rel in sorted([*manifest['files_sha256'],'package_manifest.json']):z.write(ROOT/rel,'code/'+rel)
    print('SAVED clean code-only archive:',dest,flush=True)
if __name__=='__main__':main()
