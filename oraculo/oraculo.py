#!/usr/bin/env python3
"""
oraculo.py — verificador de conformidade IEC 62443-3-3 (SR 1.3 / SR 1.7)
para os IEDs simulados, reproduzindo o comportamento do Oráculo original
do artigo (verificação de política de senha via SSH, modelo cliente-servidor).

Uso:
    python3 oraculo.py <ip_do_ied> [--user usuario_IED] [--password senha123]
"""
import argparse
import re

import paramiko


def ssh_connect(host, user, password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, username=user, password=password, timeout=10)
    return client


def run(client, cmd):
    _, stdout, stderr = client.exec_command(cmd)
    return stdout.read().decode(), stderr.read().decode()


def parse_pwquality(text):
    """Extrai minlen/dcredit/ucredit/lcredit/ocredit de pwquality.conf."""
    fields = {"minlen": 8, "dcredit": 0, "ucredit": 0, "lcredit": 0, "ocredit": 0}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"(\w+)\s*=\s*(-?\d+)", line)
        if m and m.group(1) in fields:
            fields[m.group(1)] = int(m.group(2))
    return fields


def parse_chage(text):
    """Extrai os campos do 'chage -l' (formato 'Chave: Valor' por linha)."""
    info = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        info[key.strip()] = val.strip()
    return info


def evaluate(pwq, chage_info):
    results = []

    results.append(("SR 1.3 - Comprimento mínimo da senha",
                     pwq["minlen"] >= 8, f"minlen={pwq['minlen']}"))
    results.append(("SR 1.3 - Exige dígito",
                     pwq["dcredit"] < 0, f"dcredit={pwq['dcredit']}"))
    results.append(("SR 1.3 - Exige maiúscula",
                     pwq["ucredit"] < 0, f"ucredit={pwq['ucredit']}"))
    results.append(("SR 1.3 - Exige minúscula",
                     pwq["lcredit"] < 0, f"lcredit={pwq['lcredit']}"))
    results.append(("SR 1.3 - Exige caractere especial",
                     pwq["ocredit"] < 0, f"ocredit={pwq['ocredit']}"))

    max_days_str = chage_info.get("Maximum number of days between password change", "")
    try:
        max_days = int(max_days_str)
    except ValueError:
        max_days = None
    conforme_idade = max_days is not None and 90 <= max_days <= 180
    results.append(("SR 1.7 - Troca periódica (90-180 dias)",
                     conforme_idade, f"max_days={max_days_str}"))

    return results


def print_report(host, user, results):
    print(f"\n[!] Relatório de Conformidade — {host} (usuário: {user})\n")
    for name, ok, detail in results:
        marca = "[+] Conforme" if ok else "[-] Não conforme"
        print(f"  {marca:<18} {name} ({detail})")
    total = len(results)
    conformes = sum(1 for _, ok, _ in results if ok)
    print(f"\n[*] {conformes}/{total} critérios conformes.\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("host")
    ap.add_argument("--user", default="usuario_IED")
    ap.add_argument("--password", default="senha123")
    args = ap.parse_args()

    print(f"[*] Conectando em {args.host} via SSH...")
    client = ssh_connect(args.host, args.user, args.password)
    pwq_out, _ = run(client, "cat /etc/security/pwquality.conf")
    chage_out, _ = run(client, f"chage -l {args.user}")
    client.close()

    pwq = parse_pwquality(pwq_out)
    chage_info = parse_chage(chage_out)
    results = evaluate(pwq, chage_info)
    print_report(args.host, args.user, results)


if __name__ == "__main__":
    main()
