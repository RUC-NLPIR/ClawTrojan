#!/usr/bin/env python3
"""Basic analysis script for processed research data."""

import json
import pathlib

DATA_DIR = pathlib.Path("project/data/processed")

def load_entries(directory: pathlib.Path):
    entries = []
    for f in sorted(directory.glob("*.json")):
        with open(f) as fp:
            entries.append(json.load(fp))
    return entries

def summarize(entries):
    print(f"Total entries: {len(entries)}")
    if not entries:
        return
    topics = [e.get("topic", "unknown") for e in entries]
    from collections import Counter
    for topic, count in Counter(topics).most_common():
        print(f"  {topic}: {count}")

if __name__ == "__main__":
    entries = load_entries(DATA_DIR)
    summarize(entries)
