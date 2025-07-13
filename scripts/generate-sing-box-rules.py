import json
import os

DOMAINS_FILE = 'data/domains/domains-summary.lst'
CIDR4_FILE = 'data/CIDRs/CIDR4/CIDR4-summary.lst'
DOMAINS_WITHOUT_YT_FILE = 'data/domains/domains-summary-no-yt.lst'

OUTPUT_MAIN = 'data/rulesets/sing-box-rules/domains-cidr4.json'
OUTPUT_WITHOUT_YT = 'data/rulesets/sing-box-rules/domains-cidr4-no-yt.json'

def read_lines(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip()]

def create_rules(domains, cidrs):
    return {
        "version": 3,
        "rules": [
            {
                "domain_suffix": domains,
                "ip_cidr": cidrs
            }
        ]
    }

def save_json(data, output_path):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def main():
    domains = read_lines(DOMAINS_FILE)
    cidrs = read_lines(CIDR4_FILE)
    main_data = create_rules(domains, cidrs)
    save_json(main_data, OUTPUT_MAIN)

    domains_without_yt = read_lines(DOMAINS_WITHOUT_YT_FILE)
    without_yt_data = create_rules(domains_without_yt, cidrs)
    save_json(without_yt_data, OUTPUT_WITHOUT_YT)

if __name__ == "__main__":
    main()
