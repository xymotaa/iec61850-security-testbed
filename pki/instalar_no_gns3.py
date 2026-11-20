#!/usr/bin/env python3
"""
instalar_no_gns3.py — entrega certificados e inventário aos volumes dos nós.

No GNS3 (2.2.x) cada volume persistente declarado em `extra_volumes` de um
nó Docker vive em
    <projeto>/project-files/docker/<node_id>/<caminho-do-volume>
(docker_vm.py: `os.path.join(working_dir, relpath(volume, "/"))`). O
gerador de topologia declara `/etc/8021x` em todos os nós da variante
802.1X; este script copia para ele o pacote de cada nó, a partir do que
`gerar_pki.sh` produziu. Rode com o projeto FECHADO (ou reinicie os nós).

Uso:
    python3 instalar_no_gns3.py ~/GNS3/projects/subestacao_8021x \\
        --inventario ../extracao-scd/inventario.json

Pacote por nó (nome do nó -> pasta em pki/saida/nos/):
    mesmo nome, exceto `atacante-1` -> `atacante-comprometido`, que também
    recebe `alternativos/revogado-1` e `alternativos/fora-do-inventario-1`
    (cenários E2/E3 trocam de certificado sem reinstalar nada).
    O `autenticador-8021x` recebe também o inventario.json.
"""
import argparse
import json
import shutil
import sys
from pathlib import Path

VOLUME_CERTIFICADOS = "etc/8021x"
PACOTE_DO_NO = {"atacante-1": "atacante-comprometido"}
CERTIFICADOS_ALTERNATIVOS_DO_ATACANTE = ("revogado-1", "fora-do-inventario-1")
NOME_AUTENTICADOR = "autenticador-8021x"
ARQUIVO_CHAVE = "key.pem"


class InstalacaoErro(Exception):
    pass


def localizar_projeto(caminho):
    """(pasta do projeto, arquivo .gns3) a partir de uma pasta ou do .gns3."""
    caminho = Path(caminho).expanduser()
    if caminho.is_file():
        return caminho.parent, caminho
    arquivos = sorted(caminho.glob("*.gns3"))
    if len(arquivos) != 1:
        raise InstalacaoErro(f"esperava exatamente um .gns3 em {caminho}, achei {len(arquivos)}")
    return caminho, arquivos[0]


def nos_docker(arquivo_gns3):
    with open(arquivo_gns3, encoding="utf-8") as f:
        topologia = json.load(f)
    return {n["name"]: n["node_id"] for n in topologia["topology"]["nodes"]
            if n["node_type"] == "docker"}


def copiar_pacote(origem, destino):
    if not origem.is_dir():
        raise InstalacaoErro(f"pacote inexistente: {origem} (rode pki/gerar_pki.sh)")
    destino.mkdir(parents=True, exist_ok=True)
    for arquivo in origem.iterdir():
        copia = destino / arquivo.name
        shutil.copyfile(arquivo, copia)
        copia.chmod(0o600 if arquivo.name == ARQUIVO_CHAVE else 0o644)


def instalar(projeto, pasta_pki, inventario):
    pasta_projeto, arquivo_gns3 = localizar_projeto(projeto)
    pasta_nos = Path(pasta_pki) / "nos"
    instalados = []
    for nome, node_id in nos_docker(arquivo_gns3).items():
        pacote = PACOTE_DO_NO.get(nome, nome)
        if not (pasta_nos / pacote).is_dir():
            continue
        destino = pasta_projeto / "project-files" / "docker" / node_id / VOLUME_CERTIFICADOS
        copiar_pacote(pasta_nos / pacote, destino)
        if nome == "atacante-1":
            for alternativo in CERTIFICADOS_ALTERNATIVOS_DO_ATACANTE:
                copiar_pacote(pasta_nos / alternativo, destino / "alternativos" / alternativo)
        if nome == NOME_AUTENTICADOR:
            if not Path(inventario).is_file():
                raise InstalacaoErro(f"inventário ausente: {inventario}")
            shutil.copyfile(inventario, destino / "inventario.json")
        instalados.append((nome, destino))
    if not instalados:
        raise InstalacaoErro("nenhum nó do projeto tem pacote em pki/saida/nos/")
    return instalados


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("projeto", help="pasta do projeto GNS3 (ou o arquivo .gns3)")
    ap.add_argument("--pki", default=str(Path(__file__).parent / "saida"),
                    help="saída de gerar_pki.sh (padrão: pki/saida)")
    ap.add_argument("--inventario", required=True, help="inventario.json do autenticador")
    args = ap.parse_args(argv)
    try:
        instalados = instalar(args.projeto, args.pki, args.inventario)
    except (InstalacaoErro, OSError, json.JSONDecodeError) as erro:
        print(f"[!] {erro}")
        return 1
    for nome, destino in instalados:
        print(f"[+] {nome:22s} -> {destino}")
    print("[!] Chaves privadas de LABORATÓRIO copiadas para o projeto; não versione a pasta project-files.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
