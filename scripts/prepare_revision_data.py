#!/usr/bin/env python3
"""Download/verify the pinned paper dataset and prepare the frozen positive manifest."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def tree_digest(directory):
    """Hash paths as well as contents; reject missing, extra, or edited files."""
    entries = []
    for path in sorted(directory.rglob('*')):
        if path.is_file():
            entries.append([path.relative_to(directory).as_posix(), hashlib.sha256(path.read_bytes()).hexdigest()])
    return hashlib.sha256(json.dumps(entries, separators=(',', ':')).encode()).hexdigest()


def verify_dataset(root, lock):
    from claw_trojan.loader import load_trojan_env
    paths = sorted((root / 'samples').glob('*/*.json'))
    samples = {json.loads(p.read_text())['sample_id']: p for p in paths}
    if len(paths) != len(samples) or set(samples) != set(lock['samples']):
        raise ValueError('Dataset sample IDs differ from the frozen 362-sample release')
    positive = []
    for sid, spec in lock['samples'].items():
        if hashlib.sha256(samples[sid].read_bytes()).hexdigest() != spec['metadata_sha256']:
            raise ValueError(f'Sample metadata changed: {sid}')
        if tree_digest(root / 'envs' / sid) != spec['environment_sha256']:
            raise ValueError(f'Environment differs from the paper snapshot: {sid}')
        if spec['positive']:
            steps = [s for s in load_trojan_env(str(root / 'envs' / sid)) if s.is_malicious]
            if [s.eval_id for s in steps] != spec['eval_ids']:
                raise ValueError(f'Malicious step IDs changed: {sid}')
            positive.append(dict(sample_id=sid, env_path=str((root / 'envs' / sid).resolve()),
                                 shard=spec['shard'], malicious_steps=len(steps)))
    if len(positive) != 339 or sum(r['malicious_steps'] for r in positive) != 919:
        raise ValueError('Expected 339 positive samples and 919 malicious steps')
    return positive


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, help='Verify an existing complete paper snapshot instead of downloading')
    parser.add_argument('--output-root', type=Path, default=ROOT / 'outputs/paper_revision')
    args = parser.parse_args()
    lock = json.loads((ROOT / 'reproduction/dataset_lock.json').read_text())
    root = args.source_root
    if root is None:
        from huggingface_hub import snapshot_download
        root = Path(snapshot_download(repo_id=lock['repo_id'], repo_type='dataset',
                    revision=lock['revision'], allow_patterns=['samples/**', 'envs/**'],
                    ignore_patterns=lock['excluded_snapshot_paths']))
    root = root.resolve()
    # Build an owned paper view; never remove files from a user's source or HF cache.
    view = args.output_root.resolve() / 'dataset'
    if not view.exists():
        staging = view.with_name('dataset.preparing')
        if staging.exists():
            raise ValueError(f'Unfinished preparation exists at {staging}; inspect it before retrying')
        staging.mkdir(parents=True)
        excluded = set(lock['excluded_snapshot_paths'])
        def ignore(directory, names):
            relative = Path(directory).relative_to(root)
            return [name for name in names if (relative / name).as_posix() in excluded]
        for name in ['samples', 'envs']:
            shutil.copytree(root / name, staging / name, ignore=ignore)
        verify_dataset(staging, lock)
        staging.rename(view)
    rows = verify_dataset(view, lock)
    dest = args.output_root / 'manifests/positive_samples.jsonl'
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(''.join(json.dumps(r, sort_keys=True) + '\n' for r in rows))
    print(f'Verified 362 samples; wrote 339 positive samples / 919 malicious steps to {dest}')


if __name__ == '__main__':
    main()
