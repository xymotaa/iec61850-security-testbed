#!/usr/bin/env python3
"""
oraculo.py — verificador de conformidade IEC 62443-3-3 para os IEDs
simulados, reproduzindo e ampliando o Oráculo original do artigo
(verificação via SSH, modelo cliente-servidor).

SRs cobertos:
  SR 1.1 - Identificação e autenticação de usuário humano
  SR 1.3 - Use of Strong Authentication            (original do artigo)
  SR 1.5 - Gerenciamento de autenticadores
  SR 1.7 - Password Lifetime Restrictions          (original do artigo)
  SR 2.1 - Aplicação de autorização
  SR 3.1 - Integridade da comunicação
  SR 5.1 - Segmentação de rede
  SR 7.1 - Disponibilidade de recursos

Uso:
    python3 oraculo.py <ip_do_ied> [--user usuario_IED] [--password senha123]

Nota sobre uma diferença deliberada em relação ao artigo original: o
relatório original marca 'ucredit=-1' como "Não definido", mas pela
semântica do pwquality um valor negativo significa "exigência mínima
obrigatória" (aqui, pelo menos 1 maiúscula) -- portanto isso é tratado
como CONFORME neste script, não como indefinido. "Não definido" aqui é
reservado para quando o campo realmente não aparece na configuração.

Nota sobre SR 3.1: diferente das outras, não é uma checagem de
configuração de host via SSH — é uma constatação estrutural do próprio
protocolo GOOSE (sem IEC 62351-6, não há assinatura digital nativa),
confirmada empiricamente pelo ataque de masquerade da Seção 4 deste
projeto (ver atacante/).
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


# ---------------------------------------------------------------------------
# Avaliações por SR — cada uma retorna uma lista de (label, ok, detail).
# ok=True Conforme, ok=False Não conforme, ok=None Não definido.
# ---------------------------------------------------------------------------

def evaluate_sr11(password):
    """SR 1.1 - Identificação e autenticação de usuário humano: a
    credencial usada está numa lista de senhas padrão/conhecidas?"""
    SENHAS_PADRAO_CONHECIDAS = {
        "senha123", "admin", "password", "123456", "changeme", "default",
    }
    conforme = password.lower() not in SENHAS_PADRAO_CONHECIDAS
    detail = ("senha não está numa lista de credenciais padrão conhecidas"
              if conforme else
              "senha está numa lista de credenciais padrão conhecidas")
    return [("Ausência de credencial padrão/hardcoded", conforme, detail)]


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


def evaluate_sr15(chage_info):
    """SR 1.5 - Gerenciamento de autenticadores: existe ALGUM mecanismo
    de expiração configurado (independente da janela específica de
    90-180 dias, que é o SR 1.7 abaixo)."""
    max_days_str = chage_info.get("Maximum number of days between password change", "")
    try:
        max_days = int(max_days_str)
    except ValueError:
        max_days = None
    # 99999 é o valor padrão do Linux para "nunca expira" — não conta
    # como gerenciamento de expiração de verdade.
    conforme = max_days is not None and max_days < 99999
    return [("Existência de mecanismo de expiração de senha", conforme,
              f"max_days={max_days_str}")]


def evaluate_sr17(chage_info):
    """SR 1.7 - Password Lifetime Restrictions (90 a 180 dias)."""
    max_days_str = chage_info.get("Maximum number of days between password change", "")
    try:
        max_days = int(max_days_str)
    except ValueError:
        max_days = None
    conforme = max_days is not None and 90 <= max_days <= 180
    return [("Troca periódica de senha (90-180 dias)", conforme,
              f"max_days={max_days_str}")]


def evaluate_sr21(groups_output):
    """SR 2.1 - Aplicação de autorização: a conta roda com privilégio
    mínimo, sem pertencer a grupos administrativos."""
    grupos_privilegiados = {"sudo", "wheel", "root", "admin"}
    grupos = set(groups_output.split())
    conforme = not bool(grupos & grupos_privilegiados)
    return [("Conta sem privilégios administrativos", conforme,
              f"grupos={sorted(grupos)}")]


def evaluate_sr31():
    """SR 3.1 - Integridade da comunicação: avaliação estrutural (não é
    uma configuração de host) — GOOSE puro (sem IEC 62351-6) não possui
    verificação de integridade nativa. Confirmado empiricamente pelo
    ataque de masquerade bem-sucedido na Seção 4 deste projeto."""
    detail = ("GOOSE sem IEC 62351-6 não possui assinatura digital; "
              "confirmado pelo ataque de masquerade (ver atacante/)")
    return [("Verificação de integridade das mensagens GOOSE", False, detail)]


def evaluate_sr51(vlan_output):
    """SR 5.1 - Segmentação de rede: existe VLAN separando a rede de
    processo (GOOSE/SV) da rede de estação/TI?"""
    conforme = "vlan" in vlan_output.lower()
    detail = "VLAN detectada" if conforme else "sem VLAN detectada na interface"
    return [("Segmentação de rede (VLAN) configurada", conforme, detail)]


def evaluate_sr71(sshd_config):
    """SR 7.1 - Disponibilidade de recursos: existe alguma limitação de
    taxa de conexões configurada (proteção básica contra DoS)?"""
    conforme = False
    for line in sshd_config.splitlines():
        line = line.strip()
        if line.startswith("MaxStartups"):
            valor = line.split()[-1]
            # padrão do Ubuntu é 10:30:100 (bem permissivo) — só conta
            # como conforme se foi customizado pra algo mais restritivo
            if valor != "10:30:100":
                conforme = True
    detail = "MaxStartups customizado" if conforme else "MaxStartups padrão ou ausente"
    return [("Limitação de taxa de conexões (proteção básica a DoS)", conforme, detail)]


def marca(ok):
    if ok is None:
        return "[-] Não definido"
    return "[+] Conforme" if ok else "[-] Não conforme"


def print_report(host, user, pwq, chage_info, sr_blocks):
    """sr_blocks = lista de (sr_id, titulo, resultados), na ordem em que
    devem aparecer no relatório."""
    last_change = chage_info.get("Last password change", "desconhecido")
    dias = days_since(last_change)
    dias_str = f" ({dias} dias atrás)" if dias is not None else ""

    print(f"\n[*] Conectando em {host} via SSH (usuário: {user})...\n")
    print(f"[+] Usuário '{user}' autenticado com sucesso via senha (SSH).")
    print(f"[!] Última alteração de senha: {last_change}{dias_str}\n")

    print("-> Coletando configuração remota "
          "(pwquality.conf, chage, grupos, interface, sshd_config)")
    print("Resposta do IED:\n")

    print("[!] Relatório da Configuração de Política de Senha do Equipamento\n")

    # Dump bruto dos valores de pwquality (mantém o formato do artigo original)
    sr13_results = next(r for sid, _, r in sr_blocks if sid == "1.3")
    for label, ok, detail in sr13_results:
        campo, _, valor = detail.partition("=")
        print(f"  {label} ({campo}): {valor}")
    print()

    total = 0
    conformes = 0
    for sr_id, titulo, resultados in sr_blocks:
        print(f"[!] Avaliação de Conformidade — IEC 62443-3-3 SR {sr_id} "
              f'("{titulo}")\n')
        for label, ok, detail in resultados:
            print(f"  {marca(ok):<18} {label} ({detail})")
            total += 1
            if ok is True:
                conformes += 1
        print()

    print(f"[*] {conformes}/{total} critérios conformes.\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("host")
    ap.add_argument("--user", default="usuario_IED")
    ap.add_argument("--password", default="senha123")
    args = ap.parse_args()

    client = ssh_connect(args.host, args.user, args.password)
    pwq_out, _ = run(client, "cat /etc/security/pwquality.conf")
    chage_out, _ = run(client, f"chage -l {args.user}")
    groups_out, _ = run(client, f"id -nG {args.user}")
    vlan_out, _ = run(client, "ip -d link show eth0")
    sshd_out, _ = run(client, "cat /etc/ssh/sshd_config")
    client.close()

    pwq = parse_pwquality(pwq_out)
    chage_info = parse_chage(chage_out)

    sr_blocks = [
        ("1.1", "Human user identification and authentication", evaluate_sr11(args.password)),
        ("1.3", "Use of Strong Authentication", evaluate_sr13(pwq)),
        ("1.5", "Authenticator management", evaluate_sr15(chage_info)),
        ("1.7", "Password Lifetime Restrictions", evaluate_sr17(chage_info)),
        ("2.1", "Authorization enforcement", evaluate_sr21(groups_out)),
        ("3.1", "Communication integrity", evaluate_sr31()),
        ("5.1", "Network segmentation", evaluate_sr51(vlan_out)),
        ("7.1", "Resource availability", evaluate_sr71(sshd_out)),
    ]

    print_report(args.host, args.user, pwq, chage_info, sr_blocks)


if __name__ == "__main__":
    main()
    