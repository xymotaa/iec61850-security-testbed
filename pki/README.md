# pki — PKI de TESTE para o 802.1X (EAP-TLS)

> **ATENÇÃO: são chaves de LABORATÓRIO.** A CA, os certificados e as chaves
> privadas desta pasta existem só para o testbed. Não são versionados
> (`.gitignore`), não devem ser reutilizados fora do laboratório e qualquer
> um que tenha o `saida/` consegue se passar por qualquer dispositivo.

## Gerar

```bash
cd pki
./gerar_pki.sh                 # cria pki/saida/ (use --force para recriar)
./gerar_pki.sh --ieds 8        # opcional: ubuntu-ied-1..8 (padrão 5)
```

Requer apenas `openssl`. A saída é reprodutível em estrutura (nomes, perfis),
mas as chaves são novas a cada geração.

## O que é criado

| Pacote em `saida/nos/` | Papel |
|---|---|
| `autenticador-8021x` | certificado de **servidor** (EKU serverAuth, SAN `autenticador-8021x`) + `crl.pem` |
| `ubuntu-ied-1` .. `ubuntu-ied-5` | IEDs legítimos |
| `ids-1`, `oraculo-1` | IDS e Oráculo legítimos |
| `publicador-1` | nó legítimo que publica GOOSE |
| `atacante-comprometido` | certificado **válido** de um nó invadido (cenário de limite: 802.1X autentica o dispositivo, não a mensagem) |
| `fora-do-inventario-1` | certificado válido cujo CN não consta no inventário |
| `revogado-1` | certificado **revogado** (já presente na CRL) |

Cada pasta tem `ca.pem`, `cert.pem` e `key.pem` (o autenticador também `crl.pem`)
e está pronta para ser copiada em `/etc/8021x` do nó. O CN do certificado é o
nome do nó no GNS3 — é ele que o inventário vincula ao MAC.

Revogar mais um dispositivo com o autenticador rodando:

```bash
./gerar_pki.sh --revogar ubuntu-ied-2
# copie saida/nos/autenticador-8021x/crl.pem para /etc/8021x do autenticador, então, no console dele:
autenticador-ctl recarregar-crl
autenticador-ctl reautenticar
```

## Como os certificados chegam aos nós Docker do GNS3

Escolha: **volume persistente do nó** (`extra_volumes`), não `COPY` no build.
Motivo: cada nó precisa de um certificado/chave diferentes e uma imagem por
dispositivo seria desproporcional; além disso, trocar o certificado (cenários
E2/E3) não exige rebuild. No GNS3 2.2.x o volume `/etc/8021x` de um nó vive em

```
<projeto>/project-files/docker/<node_id>/etc/8021x/
```

(código do `gns3server`: `docker_vm.py`, `os.path.join(working_dir, relpath(volume, "/"))`).
O gerador de topologia já declara esse volume nos nós da variante 802.1X.
Para preenchê-lo:

```bash
python3 instalar_no_gns3.py ~/GNS3/projects/subestacao_8021x \
    --inventario ../extracao-scd/inventario.json
```

O script lê o `.gns3`, descobre o `node_id` de cada nó e copia o pacote certo
(`atacante-1` recebe `atacante-comprometido` e, em `alternativos/`, `revogado-1`
e `fora-do-inventario-1`; o `autenticador-8021x` recebe também o
`inventario.json`). Rode com o projeto fechado ou reinicie os nós depois.

> Não foi possível testar o GNS3 em si neste ambiente; o caminho acima foi
> confirmado lendo o código do `gns3server` instalado (2.2.x), e o script é
> coberto por teste unitário com projeto falso.
