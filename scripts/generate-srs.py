#!/usr/bin/env python3
import os
import sys
import shutil
import tarfile
import subprocess
from pathlib import Path
import requests
import json

# SETTINGS
SING_BOX_VERSION = os.getenv("SING_BOX_VERSION", "1.11.15")
WORK_DIR = Path(".")
DOWNLOAD_URL = (
    f"https://github.com/SagerNet/sing-box/releases/download/"
    f"v{SING_BOX_VERSION}/sing-box-{SING_BOX_VERSION}-linux-amd64.tar.gz"
)
TARBALL = WORK_DIR / f"sing-box-{SING_BOX_VERSION}-linux-amd64.tar.gz"
EXTRACT_DIR = WORK_DIR / f"sing-box-{SING_BOX_VERSION}-linux-amd64"
CIDR_FILE = Path("data/CIDRs/CIDR4/CIDR4-summary.lst")
DOMAINS_FILE = Path("data/domains/domains-summary.lst")
DOMAINS_NOYT_FILE = Path("data/domains/domains-summary-no-yt.lst")

RULES_JSON = WORK_DIR / "rules.json"
RULES_JSON_NOYT = WORK_DIR / "rules-no-yt.json"

OUTPUT_SRS = Path("data/rulesets/SRS/domains-cidr4.srs")
OUTPUT_SRS_NOYT = Path("data/rulesets/SRS/domains-cidr4-no-yt.srs")


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


def build_rules_json():
    if not CIDR_FILE.exists() or not DOMAINS_FILE.exists():
        print("Отсутствуют CIDR или domains файлы", file=sys.stderr)
        sys.exit(1)

    print("Генерируем rules.json и rules-no-yt.json")

    with open(DOMAINS_FILE) as f:
        domains_all = {d.strip() for d in f if d.strip()}

    with open(CIDR_FILE) as f:
        cidrs = [c.strip() for c in f if c.strip()]

    # подстановка ".ua"
    domains_all = {".ua" if d == "ua" else d for d in domains_all}

    # читаем исключения no-yt
    if DOMAINS_NOYT_FILE.exists():
        with open(DOMAINS_NOYT_FILE) as f:
            domains_noyt = {d.strip() for d in f if d.strip()}
        domains_noyt = {".ua" if d == "ua" else d for d in domains_noyt}
    else:
        domains_noyt = set()

    # payload для всех доменов
    payload_all = {
        "version": 3,
        "rules": [
            {
                "domain_suffix": sorted(domains_all),
                "ip_cidr": cidrs
            }
        ]
    }

    # payload для no-yt (исключаем домены)
    domains_filtered = domains_all - domains_noyt

    if domains_filtered:
        payload_noyt = {
            "version": 3,
            "rules": [
                {
                    "domain_suffix": sorted(domains_filtered),
                    "ip_cidr": cidrs
                }
            ]
        }
    else:
        payload_noyt = None
        print("Внимание: после исключения доменов no-yt список пуст, rules-no-yt.json не будет создан.")

    # Записываем файлы
    with open(RULES_JSON, "w") as f:
        json.dump(payload_all, f, indent=2)

    if payload_noyt:
        with open(RULES_JSON_NOYT, "w") as f:
            json.dump(payload_noyt, f, indent=2)
    else:
        if RULES_JSON_NOYT.exists():
            RULES_JSON_NOYT.unlink()


def compile_srs():
    bin_path = EXTRACT_DIR / "sing-box"
    if not bin_path.exists():
        print("sing-box бинарь не найден", file=sys.stderr)
        sys.exit(1)

    print("Компилируем SRS правила")

    # Создаем уникальные временные файлы
    temp_srs_all = WORK_DIR / "temp_rules_all.srs"
    temp_srs_noyt = WORK_DIR / "temp_rules_noyt.srs"

    # Компиляция обычного rules.json
    subprocess.run(
        [str(bin_path), "rule-set", "compile", str(RULES_JSON), "-o", str(temp_srs_all)],
        check=True
    )
    os.makedirs(OUTPUT_SRS.parent, exist_ok=True)
    if temp_srs_all.exists():
        shutil.move(temp_srs_all, OUTPUT_SRS)
        print(f"Сгенерирован {OUTPUT_SRS}")
    else:
        print(f"Файл {temp_srs_all} не найден после первой компиляции", file=sys.stderr)
        sys.exit(1)

    # Компиляция no-yt версии (если есть)
    if RULES_JSON_NOYT.exists():
        print("\nКомпилируем no-yt правила:")
        print(f"Файл {RULES_JSON_NOYT} размер: {RULES_JSON_NOYT.stat().st_size} байт")
        
        subprocess.run(
            [str(bin_path), "rule-set", "compile", str(RULES_JSON_NOYT), "-o", str(temp_srs_noyt)],
            check=True
        )
        if temp_srs_noyt.exists():
            shutil.move(temp_srs_noyt, OUTPUT_SRS_NOYT)
            print(f"Сгенерирован {OUTPUT_SRS_NOYT}")
        else:
            print(f"Файл {temp_srs_noyt} не найден после компиляции no-yt", file=sys.stderr)
            sys.exit(1)
    else:
        print("Файл rules-no-yt.json не найден, компиляция no-yt пропущена.")


def cleanup():
    for p in [TARBALL, RULES_JSON, RULES_JSON_NOYT]:
        if p.exists():
            p.unlink()
    if EXTRACT_DIR.exists():
        shutil.rmtree(EXTRACT_DIR)
    # Удаляем временные SRS файлы, если остались
    for temp in [WORK_DIR / "temp_rules_all.srs", WORK_DIR / "temp_rules_noyt.srs"]:
        if temp.exists():
            temp.unlink()


if __name__ == "__main__":
    try:
        download_and_extract()
        build_rules_json()
        compile_srs()
    finally:
        cleanup()