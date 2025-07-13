#!/usr/bin/env python3
import os
import json
from pathlib import Path

DOMAINS_FILE = Path("data/domains/domains-summary.lst")
CIDR_FILE = Path("data/CIDRs/CIDR4/CIDR4-summary.lst")
OUTPUT_JSON = Path("data/rulesets/nekoray-mahdi.json")

def load_list(path):
    return [line.strip() for line in path.read_text().splitlines() if line.strip()]

def main():
    if not DOMAINS_FILE.exists() or not CIDR_FILE.exists():
        print("domains.lst или summary-cidr4.lst не найдены")
        return

    domains = load_list(DOMAINS_FILE)
    domains = [".ua" if d == "ua" else d for d in domains]
    cidrs = load_list(CIDR_FILE)

    routing = {
      "id": 222222223,
      "name": "routing",
      "rules": [
        {
          "actionType": "hijack-dns",
          "invert": False,
          "ip_is_private": False,
          "ip_version": "",
          "name": "rule_1",
          "network": "",
          "noDrop": False,
          "outboundID": -2,
          "override_address": "",
          "override_port": 0,
          "protocol": "dns",
          "rejectMethod": "",
          "simple_action": 0,
          "sniffOverrideDest": False,
          "source_ip_is_private": False,
          "strategy": "",
          "type": 0
        },
        {
          "actionType": "route",
          "domain_suffix": domains,
          "invert": False,
          "ip_is_private": False,
          "ip_version": "",
          "name": "rule_2",
          "network": "",
          "noDrop": False,
          "outboundID": -1,
          "override_address": "",
          "override_port": 0,
          "protocol": "",
          "rejectMethod": "",
          "simple_action": 0,
          "sniffOverrideDest": False,
          "source_ip_is_private": False,
          "strategy": "",
          "type": 0
        },
        {
          "actionType": "route",
          "ip_cidr": cidrs,
          "invert": False,
          "ip_is_private": False,
          "ip_version": "",
          "name": "rule_3",
          "network": "",
          "noDrop": False,
          "outboundID": -1,
          "override_address": "",
          "override_port": 0,
          "protocol": "",
          "rejectMethod": "",
          "simple_action": 1600940404,
          "sniffOverrideDest": False,
          "source_ip_is_private": False,
          "strategy": "",
          "type": 0
        },
        {
          "actionType": "route",
          "invert": False,
          "ip_is_private": False,
          "ip_version": "",
          "name": "rule_4",
          "network": "",
          "noDrop": False,
          "outboundID": -2,
          "override_address": "",
          "override_port": 0,
          "process_name": ["Discord.exe"],
          "protocol": "",
          "rejectMethod": "",
          "simple_action": 0,
          "sniffOverrideDest": False,
          "source_ip_is_private": False,
          "strategy": "",
          "type": 0
        }
      ]
    }

    os.makedirs(OUTPUT_JSON.parent, exist_ok=True)
    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(routing, f, ensure_ascii=False, indent=2)

    print(f"Сгенерирован {OUTPUT_JSON}")

if __name__ == "__main__":
    main()
