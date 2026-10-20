#!/usr/bin/env python3
"""Summarizes a load-test run (tests/load/run.sh): per service, peak and mean
CPU (in vCPUs) and memory; the box's services' memory together (SeaweedFS
stands in for R2 and is left out); Postgres's connections and commit rate;
and the generator's report.

    tests/load/summarize.py <results>/<label> [...]
"""
import json
import re
import sys
from collections import defaultdict

UNITS = {"B": 1, "KiB": 1024, "MiB": 1024**2, "GiB": 1024**3, "kB": 1000, "MB": 1000**2, "GB": 1000**3}


def mib(text):
    match = re.match(r"([\d.]+)\s*([A-Za-z]+)", text.strip())
    return float(match.group(1)) * UNITS[match.group(2)] / 1024**2 if match else 0.0


def summarize(run):
    cpu, mem, at = defaultdict(list), defaultdict(list), defaultdict(dict)
    for line in open(f"{run}/containers.csv"):
        parts = line.strip().split(",")
        if len(parts) != 4:
            continue
        stamp, name, percent, usage = parts
        # <project>-<service>-<n>, the project being kutup-load (or another).
        service = re.sub(r"-\d+$", "", name)
        service = re.sub(r"^kutup-load-", "", service)
        cpu[service].append(float(percent.rstrip("%") or 0) / 100)
        used = mib(usage.split("/")[0])
        mem[service].append(used)
        at[stamp][service] = used
    print(f"== {run}")
    print(f"{'service':22} {'cpu peak':>9} {'cpu mean':>9} {'mem peak MiB':>13} {'mem mean MiB':>13}")
    for service in sorted(cpu):
        c, m = cpu[service], mem[service]
        print(f"{service:22} {max(c):9.2f} {sum(c)/len(c):9.2f} {max(m):13.0f} {sum(m)/len(m):13.0f}")
    box = [sum(v for s, v in services.items() if not s.startswith("seaweedfs")) for services in at.values()]
    if box:
        print(f"box services' memory together: peak {max(box):.0f} MiB of 4096")
    rows = [l.strip().split("|") for l in open(f"{run}/postgres.csv") if l.count("|") == 4]
    if rows:
        connections = [int(r[1]) for r in rows]
        active = [int(r[2]) for r in rows]
        longest = [float(r[4]) for r in rows]
        commits = [(int(r[0]), int(r[3])) for r in rows]
        rate = (commits[-1][1] - commits[0][1]) / max(1, commits[-1][0] - commits[0][0])
        print(f"postgres: connections peak {max(connections)}, active peak {max(active)}, "
              f"longest running query {max(longest):.2f}s, {rate:.0f} commits/s")
    try:
        gen = [l.strip().split(",") for l in open(f"{run}/generator.csv") if l.count(",") == 2]
        if gen:
            print(f"generator: cpu peak {max(float(g[1]) for g in gen)/100:.2f} cores, "
                  f"memory peak {max(int(g[2]) for g in gen)/1024:.0f} MiB")
    except FileNotFoundError:
        pass
    try:
        report = json.load(open(f"{run}/report.json"))
        print(f"{'operation':22} {'ok':>7} {'err':>5} {'per s':>7} {'p50':>8} {'p95':>8} {'p99':>8}")
        for o in report["operations"]:
            print(f"{o['operation']:22} {o['ok']:7} {o['errors']:5} {o['perSecond']:7.1f} "
                  f"{o['p50Ms']:8.1f} {o['p95Ms']:8.1f} {o['p99Ms']:8.1f} {o['errorKinds'] or ''}")
    except FileNotFoundError:
        print("no report.json")


for run in sys.argv[1:]:
    summarize(run.rstrip("/"))
