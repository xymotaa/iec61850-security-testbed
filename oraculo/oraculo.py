#!/usr/bin/env python3
"""
oraculo.py — verificador de conformidade IEC 62443-3-3 (SR 1.3 / SR 1.7)
para os IEDs simulados, reproduzindo o comportamento do Oráculo original
do artigo (verificação de política de senha via SSH, modelo cliente-servidor).

Uso:
    python3 oraculo.py <ip_do_ied> [--user usuario_IED] [--password senha123]

Nota sobre uma diferença deliberada em relação ao artigo original: o
relatório original marca 'ucredit=-1' como "Não definido", mas pela
semântica do pwquality um valor negativo significa "exigência mínima
obrigatória" (aqui, pelo menos 1 maiúscula) -- portanto isso é tratado
como CONFORME neste script, não como indefinido. "Não definido" aqui é
reservado para quando o campo realmente não aparece na configuração.
"""
import argparse
from datetime import datetime
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
    """Extrai minlen/dcredit/ucredit/lcredit/ocredit de pwquality.conf.
    Retorna None para um campo que não aparece no arquivo (indefinido de
    verdade), em vez de assumir um padrão silenciosamente."""
    fields = {"minlen": None, "dcredit": None, "ucredit": None,
              "lcredit": None, "ocredit": None}
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


def days_since(date_str):
    """Converte uma data no formato do chage (ex: 'Sep 10, 2026') em
    'há quantos dias' a partir de hoje. Retorna None se não der pra
    interpretar (ex: 'never')."""
    try:
        d = datetime.strptime(date_str.strip(), "%b %d, %Y")
    except ValueError:
        return None
    return (datetime.now() - d).days


def evaluate_sr13(pwq):
    """SR 1.3 - Use of Strong Authentication."""
    results = []

    minlen = pwq["minlen"]
    results.append(("Comprimento mínimo da senha (8-14 caracteres)",
                     minlen is not None and 8 <= minlen <= 14,
                     f"minlen={minlen}"))

    for label, key in [("Mínimo de dígitos (0-9)", "dcredit"),
                        ("Mínimo de maiúsculas (A-Z)", "ucredit"),
                        ("Mínimo de minúsculas (a-z)", "lcredit"),
                        ("Mínimo de caracteres especiais", "ocredit")]:
        val = pwq[key]
        if val is None:
            results.append((label, None, f"{key}=indefinido"))
        else:
            # negativo = exige no mínimo |val| caracteres dessa classe
            results.append((label, val < 0, f"{key}={val}"))

    return results


def evaluate_sr17(chage_info):
    """SR 1.7 - Password Lifetime Restrictions (90 a 180 dias)."""
    max_days_str = chage_info.get("Maximum number of days between password change", "")
    try:
        max_days = int(max_days_str)
    except ValueError:
        max_days = None
    conforme = max_days is not None and 90 <= max_days <= 180
    return [("Troca periódica de senha (90-180 dias)", conforme, f"max_days={max_days_str}")]


def marca(ok):
    if ok is None:
        return "[-] Não definido"
    return "[+] Conforme" if ok else "[-] Não conforme"


def print_report(host, user, pwq, chage_info, sr13, sr17):
    last_change = chage_info.get("Last password change", "desconhecido")
    dias = days_since(last_change)
    dias_str = f" ({dias} dias atrás)" if dias is not None else ""

    print(f"\n[*] Conectando em {host} via SSH (usuário: {user})...\n")
    print(f"[+] Usuário '{user}' autenticado com sucesso via senha (SSH).")
    print(f"[!] Última alteração de senha: {last_change}{dias_str}\n")

    print("-> Coletando configuração remota "
          "(cat /etc/security/pwquality.conf; chage -l)")
    print("Resposta do IED:\n")

    print("[!] Relatório da Configuração de Política de Senha do Equipamento\n")
    for label, ok, detail in sr13:
        campo = detail.split("=")[0]
        valor = detail.split("=")[1]
        print(f"  {label} ({campo}): {valor}")

    print(f"\n[!] Avaliação de Conformidade — IEC 62443-3-3 SR 1.3 "
          f'("Use of Strong Authentication")\n')
    for label, ok, detail in sr13:
        print(f"  {marca(ok):<18} {label}")

    print(f"\n[!] Avaliação de Conformidade — IEC 62443-3-3 SR 1.7 "
          f'("Password Lifetime Restrictions")\n')
    for label, ok, detail in sr17:
        print(f"  {marca(ok):<18} {label} ({detail})")

    todos = sr13 + sr17
    total = len(todos)
    conformes = sum(1 for _, ok, _ in todos if ok is True)
    print(f"\n[*] {conformes}/{total} critérios conformes.\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("host")
    ap.add_argument("--user", default="usuario_IED")
    ap.add_argument("--password", default="senha123")
    args = ap.parse_args()

    client = ssh_connect(args.host, args.user, args.password)
    pwq_out, _ = run(client, "cat /etc/security/pwquality.conf")
    chage_out, _ = run(client, f"chage -l {args.user}")
    client.close()

    pwq = parse_pwquality(pwq_out)
    chage_info = parse_chage(chage_out)
    sr13 = evaluate_sr13(pwq)
    sr17 = evaluate_sr17(chage_info)

    print_report(args.host, args.user, pwq, chage_info, sr13, sr17)


if __name__ == "__main__":
    main()
