#!/usr/bin/env python3
import os
import sys
import shutil
import tarfile
import subprocess
from pathlib import Path
import requests
import json
from concurrent.futures import ThreadPoolExecutor

SING_BOX_VERSION = os.getenv("SING_BOX_VERSION", "1.11.15")
WORK_DIR = Path(".")
DOWNLOAD_URL = (
    f"https://github.com/SagerNet/sing-box/releases/download/"
    f"v{SING_BOX_VERSION}/sing-box-{SING_BOX_VERSION}-linux-amd64.tar.gz"
)
TARBALL = WORK_DIR / f"sing-box-{SING_BOX_VERSION}-linux-amd64.tar.gz"
EXTRACT_DIR = WORK_DIR / f"sing-box-{SING_BOX_VERSION}-linux-amd64"

INPUT_DIRS = [
    Path("data/domains/groups"),
    Path("data/domains/services"),
    Path("data/CIDRs")
]

# ==================================================
# БЛОК ДЛЯ SING-BOX-RULES (РАСКОММЕНТИРОВАТЬ ПОТОМ)
# ==================================================

SPECIAL_FILES = [
    Path("data/domains/domains-summary.lst"),
    Path("data/domains/domains-summary-no-yt.lst")
]

CIDR4_SUMMARY = Path("data/CIDRs/CIDR4/CIDR4-summary.lst")
CIDR6_SUMMARY = Path("data/CIDRs/CIDR6/CIDR6-summary.lst")
INCLUDE_CIDR6 = False

SING_BOX_RULES_DIR = Path("data/rulesets/sing-box-rules")
ALL_RULES_DIR = SING_BOX_RULES_DIR / "all"

def process_special_file(lst_file, bin_path):
    try:
        temp_json = WORK_DIR / f"temp_special_{lst_file.stem}.json"
        
        with open(lst_file) as f:
            items = {item.strip() for item in f if item.strip()}
            items = {".ua" if d == "ua" else d for d in items}
        
        payload = {
            "version": 3,
            "rules": [{"domain_suffix": sorted(items)}]
        }
        
        with open(temp_json, "w") as f:
            json.dump(payload, f, indent=2)
        
        output_dir = SING_BOX_RULES_DIR
        output_dir.mkdir(parents=True, exist_ok=True)
        output_srs = output_dir / lst_file.with_suffix('.srs').name
        output_json = output_dir / lst_file.with_suffix('.json').name
        
        temp_srs = WORK_DIR / f"temp_special_{lst_file.stem}.srs"
        
        subprocess.run(
            [str(bin_path), "rule-set", "compile", str(temp_json), "-o", str(temp_srs)],
            check=True
        )
        
        if temp_srs.exists():
            shutil.move(temp_srs, output_srs)
            print(f"Сгенерирован {output_srs}")
        
        shutil.move(temp_json, output_json)
        print(f"Сохранен {output_json}")
        
    except Exception as e:
        print(f"Ошибка обработки {lst_file}: {str(e)}", file=sys.stderr)

def create_combined_rules(bin_path):
    if not CIDR4_SUMMARY.exists():
        print(f"Файл {CIDR4_SUMMARY} не найден, пропускаем создание объединённых правил")
        return

    ALL_RULES_DIR.mkdir(parents=True, exist_ok=True)
    
    with open(CIDR4_SUMMARY) as f:
        cidr4_items = {item.strip() for item in f if item.strip()}
    
    domains_no_yt_file = Path("data/domains/domains-summary-no-yt.lst")
    if not domains_no_yt_file.exists():
        print(f"Файл {domains_no_yt_file} не найден, пропускаем создание объединённых правил")
        return
    
    with open(domains_no_yt_file) as f:
        domains_no_yt = {item.strip() for item in f if item.strip()}
        domains_no_yt = {".ua" if d == "ua" else d for d in domains_no_yt}
    
    combined_json = ALL_RULES_DIR / "all-rules.json"
    payload = {
        "version": 3,
        "rules": [
            {
                "domain_suffix": sorted(domains_no_yt),
                "ip_cidr": sorted(cidr4_items)
            }
        ]
    }
    
    with open(combined_json, "w") as f:
        json.dump(payload, f, indent=2)
    
    combined_srs = ALL_RULES_DIR / "all-rules.srs"
    temp_srs = WORK_DIR / "temp_all_rules.srs"
    
    subprocess.run(
        [str(bin_path), "rule-set", "compile", str(combined_json), "-o", str(temp_srs)],
        check=True
    )
    
    if temp_srs.exists():
        shutil.move(temp_srs, combined_srs)
        print(f"Созданы объединённые правила в {combined_srs}")
    else:
        print("Ошибка при создании объединённых правил", file=sys.stderr)

# ==================================================
# КОНЕЦ БЛОКА ДЛЯ SING-BOX-RULES
# ==================================================

def find_lst_files():
    """Находит все .lst файлы в INPUT_DIRS"""
    lst_files = []
    for input_dir in INPUT_DIRS:
        if input_dir.exists():
            for root, _, files in os.walk(input_dir):
                for file in files:
                    if file.endswith('.lst'):
                        lst_files.append(Path(root) / file)
    return lst_files

def process_regular_file(lst_file, bin_path):
    """Обрабатывает обычные файлы (не special)"""
    try:
        is_cidr = "CIDRs" in str(lst_file)
        is_cidr4 = "CIDR4" in str(lst_file)
        is_cidr6 = "CIDR6" in str(lst_file)

        temp_prefix = "_cidr4" if is_cidr4 else "_cidr6" if is_cidr6 else ""

        temp_json = WORK_DIR / f"temp{temp_prefix}_{lst_file.stem}.json"
        
        with open(lst_file) as f:
            items = {item.strip() for item in f if item.strip()}
        
        if is_cidr:
            payload = {
                "version": 3,
                "rules": [{"ip_cidr": sorted(items)}]
            }
        else:
            items = {".ua" if d == "ua" else d for d in items}
            payload = {
                "version": 3,
                "rules": [{"domain_suffix": sorted(items)}]
            }
        
        with open(temp_json, "w") as f:
            json.dump(payload, f, indent=2)
        
        output_srs = lst_file.with_suffix('.srs')
        output_json = lst_file.with_suffix('.json')
        
        temp_srs = WORK_DIR / f"temp{temp_prefix}_{lst_file.stem}.srs"
        
        subprocess.run(
            [str(bin_path), "rule-set", "compile", str(temp_json), "-o", str(temp_srs)],
            check=True
        )
        
        if temp_srs.exists():
            shutil.move(temp_srs, output_srs)
            print(f"Сгенерирован {output_srs}")
        
        shutil.move(temp_json, output_json)
        print(f"Сохранен {output_json}")
        
    except Exception as e:
        print(f"Ошибка обработки {lst_file}: {str(e)}", file=sys.stderr)

def download_and_extract():
    print(f"Скачиваем {DOWNLOAD_URL}")
    resp = requests.get(DOWNLOAD_URL, stream=True)
    resp.raise_for_status()
    with open(TARBALL, "wb") as fd:
        for chunk in resp.iter_content(1024 * 1024):
            fd.write(chunk)

    print(f"Распаковываем {TARBALL}")
    with tarfile.open(TARBALL) as tar:
        tar.extractall()

    if not EXTRACT_DIR.exists():
        print("Ошибка распаковки", file=sys.stderr)
        sys.exit(1)

def main():
    try:
        download_and_extract()
        bin_path = EXTRACT_DIR / "sing-box"
        if not bin_path.exists():
            print("sing-box бинарь не найден", file=sys.stderr)
            sys.exit(1)
        
        lst_files = find_lst_files()
        if not lst_files:
            print("Не найдены .lst файлы для обработки", file=sys.stderr)
            sys.exit(1)
        
        print(f"Найдено {len(lst_files)} .lst файлов для обработки")
        
        with ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
            for lst_file in lst_files:
                executor.submit(process_regular_file, lst_file, bin_path)
        
        """
        # ==================================================
        # ВЫЗОВ ФУНКЦИЙ ДЛЯ SING-BOX-RULES (РАСКОММЕНТИРОВАТЬ ПОТОМ)
        for special_file in SPECIAL_FILES:
            if special_file.exists():
                process_special_file(special_file, bin_path)
        create_combined_rules(bin_path)
        # ==================================================
        """
                
    finally:
        for p in [TARBALL]:
            if p.exists():
                p.unlink()
        if EXTRACT_DIR.exists():
            shutil.rmtree(EXTRACT_DIR)

if __name__ == "__main__":
    main()
