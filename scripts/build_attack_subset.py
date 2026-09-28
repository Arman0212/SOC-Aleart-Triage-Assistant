"""Build src/nullpunkt/attack/data/attack_subset.json from MITRE's official STIX data.

    python scripts/build_attack_subset.py              # pinned ATT&CK version, downloaded
    python scripts/build_attack_subset.py --from-file enterprise-attack-19.2.json

Keeps the enterprise tactics in kill-chain order and every technique the detection rule catalog
uses (plus parents of sub-techniques), with names and official tactics. The output is committed
as package data, so the pipeline never needs the network or the 50 MB bundle at runtime.
Re-run it only when the rule catalog or the pinned ATT&CK version changes.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from pathlib import Path

from nullpunkt.core.detection_rules import RULES

ATTACK_VERSION = "19.2"
URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack-{version}.json"
)
OUT = Path(__file__).resolve().parents[1] / "src/nullpunkt/attack/data/attack_subset.json"


def _external_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def _live(obj: dict) -> bool:
    return not obj.get("revoked") and not obj.get("x_mitre_deprecated")


def build(bundle: dict, version: str, source: str) -> dict:
    objects = bundle["objects"]
    collection = [o for o in objects if o["type"] == "x-mitre-collection"]
    if collection and collection[0].get("x_mitre_version") != version:
        raise SystemExit(f"bundle is ATT&CK {collection[0].get('x_mitre_version')}, not {version}")

    tactics_by_ref = {o["id"]: o for o in objects if o["type"] == "x-mitre-tactic" and _live(o)}
    matrix = next(o for o in objects if o["type"] == "x-mitre-matrix" and _live(o))
    tactics = [
        {
            "id": _external_id(tactics_by_ref[ref]),
            "shortname": tactics_by_ref[ref]["x_mitre_shortname"],
            "name": tactics_by_ref[ref]["name"],
        }
        for ref in matrix["tactic_refs"]
    ]

    all_techniques = {}
    for o in objects:
        if o["type"] == "attack-pattern" and _live(o):
            phases = [
                p["phase_name"]
                for p in o.get("kill_chain_phases", [])
                if p["kill_chain_name"] == "mitre-attack"
            ]
            all_techniques[_external_id(o)] = {"name": o["name"], "tactics": phases}

    wanted = set()
    for rule in RULES:
        wanted.add(rule.technique)
        wanted.add(rule.technique.split(".")[0])
    missing = sorted(wanted - set(all_techniques))
    if missing:
        raise SystemExit(f"techniques not in ATT&CK {version}: {missing}")

    order = [t["shortname"] for t in tactics]
    techniques = {}
    for tid in sorted(wanted):
        entry = all_techniques[tid]
        techniques[tid] = {
            "name": entry["name"],
            "tactics": sorted(entry["tactics"], key=order.index),
        }
    return {
        "attack_version": version,
        "domain": "enterprise-attack",
        "source": source,
        "tactics": tactics,
        "techniques": techniques,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build the ATT&CK subset used by nullpunkt.")
    parser.add_argument("--version", default=ATTACK_VERSION)
    parser.add_argument("--from-file", type=Path, help="use a local STIX bundle")
    parser.add_argument("--out", type=Path, default=OUT)
    args = parser.parse_args(argv)

    url = URL.format(version=args.version)
    if args.from_file:
        bundle = json.loads(args.from_file.read_text(encoding="utf-8"))
    else:
        with urllib.request.urlopen(url, timeout=300) as response:  # noqa: S310 (fixed https URL)
            bundle = json.load(response)
    subset = build(bundle, args.version, url)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(subset, indent=2) + "\n", encoding="utf-8")
    print(
        f"wrote {args.out}: ATT&CK {subset['attack_version']}, {len(subset['tactics'])} tactics, "
        f"{len(subset['techniques'])} techniques"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
