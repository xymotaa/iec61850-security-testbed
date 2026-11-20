# Guia de testes — 5º Marco (IEEE 802.1X + EAP-TLS)

Pré-requisito: passo a passo de `autenticador-8021x/README.md` (imagens,
`pki/gerar_pki.sh`, topologia `subestacao_8021x`, `pki/instalar_no_gns3.py`).

Valores usados abaixo:

| Item | Valor |
|---|---|
| `MAC_PUBLICADOR` | `00:30:a7:01:b3:16` (origem do GOOSE do `molde.pcap`) |
| `MAC_IED1` | `02:00:c0:a8:0a:0b` |
| `MAC_ATACANTE` | `02:00:c0:a8:0a:28` |
| IPs | `ubuntu-ied-1` .11, `ubuntu-ied-2` .12, `oraculo-1` .20, `ids-1` .30, `atacante-1` .40, `publicador-1` .50 |
| Chave HMAC de teste | `chave-de-teste` |

## 1. Subir a topologia

GNS3: abrir `subestacao_8021x` → **Ctrl+A** → **Start** → esperar ~30s.

Consoles: `autenticador-8021x`, `ids-1`, `publicador-1`, `atacante-1`, `oraculo-1`, `ubuntu-ied-1`.

Verificação de base (console `autenticador-8021x`):

```bash
autenticador-ctl estado
grep auth_aceita /var/log/8021x/eventos.jsonl
```

Esperado: um `auth_aceita` para `ubuntu-ied-1`, `ubuntu-ied-2`, `oraculo-1`, `ids-1`, `publicador-1`; **nenhum** para `atacante-1` (ele não liga o supplicant sozinho).

Console `ubuntu-ied-1`:

```bash
8021x-supplicant status
ping -c 3 192.168.10.12
```

Console `oraculo-1` (serviço legítimo continua funcionando):

```bash
python3 oraculo.py 192.168.10.11
```

## E0 — Referência: rede SEM 802.1X (C1 passa)

Console `autenticador-8021x`:

```bash
autenticador-ctl desativar
```

Console `ids-1`:

```bash
python3 ids.py --iface eth0 --log /tmp/alertas_e0.jsonl
```

Console `publicador-1` (baseline do `gocbRef` no IDS):

```bash
python3 goose_attack.py replay --iface eth0 --template molde.pcap --delay 3
```

Console `atacante-1` (sem supplicant, MAC clonado do publicador):

```bash
ip link set eth0 down; ip link set eth0 address 00:30:a7:01:b3:16; ip link set eth0 up
python3 goose_attack.py masquerade --iface eth0 --template molde.pcap --occurrence 0
```

Esperado: o frame chega à rede e o IDS **não** alerta (C1, igual ao 4º Marco).

Coletar: print do console do `ids-1` e `/tmp/alertas_e0.jsonl`.

Voltar ao 802.1X (console `autenticador-8021x`; depois, em cada nó legítimo, religar o supplicant):

```bash
autenticador-ctl ativar
```

Consoles `ubuntu-ied-1`, `ubuntu-ied-2`, `oraculo-1`, `ids-1`, `publicador-1`:

```bash
8021x-supplicant start
```

Console `atacante-1` (restaurar o MAC):

```bash
ip link set eth0 down; ip link set eth0 address 02:00:c0:a8:0a:28; ip link set eth0 up
```

## E1 — Atacante SEM certificado, MAC clonado: bloqueado antes do IDS

Console `ids-1` (deixar rodando):

```bash
python3 ids.py --iface eth0 --log /tmp/alertas_e1.jsonl
```

Console `publicador-1` (baseline):

```bash
python3 goose_attack.py replay --iface eth0 --template molde.pcap --delay 3
```

Console `atacante-1` (supplicant desligado, MAC do publicador):

```bash
ip link set eth0 down; ip link set eth0 address 00:30:a7:01:b3:16; ip link set eth0 up
python3 goose_attack.py masquerade --iface eth0 --template molde.pcap --occurrence 0
ping -c 3 -W 2 192.168.10.12
```

Console `autenticador-8021x`:

```bash
nft list set bridge acesso8021x descartados
grep quadro_descartado /var/log/8021x/eventos.jsonl | tail -n 5
```

Esperado: o `ids-1` **não recebe nada** do atacante (nenhum alerta novo); o `ping` falha; o par (porta do atacante, `00:30:a7:01:b3:16`) aparece em `descartados` com contador > 0 e como `quadro_descartado`. Não há `auth_rejeitada`: sem supplicant não há EAPOL.

Coletar: `/tmp/alertas_e1.jsonl` (vazio de alertas do ataque), saída do `nft list set`, linhas `quadro_descartado` do `eventos.jsonl`.

## E2 — Certificado REVOGADO: rejeitado

Console `atacante-1` (MAC próprio):

```bash
ip link set eth0 down; ip link set eth0 address 02:00:c0:a8:0a:28; ip link set eth0 up
AUTH_8021X_CERT_DIR=/etc/8021x/alternativos/revogado-1 AUTH_8021X_TIMEOUT=15 8021x-supplicant start
ping -c 3 -W 2 192.168.10.12
8021x-supplicant stop
```

Console `autenticador-8021x`:

```bash
grep auth_rejeitada /var/log/8021x/eventos.jsonl | tail -n 3
```

Esperado: `auth_rejeitada` com `"cn": "revogado-1"` e `"motivo": "certificado_revogado"`; supplicant fica `Unauthorized`; o `ping` falha.

Coletar: linha do `eventos.jsonl`, saída do `8021x-supplicant start`.

### E2b — Revogação em operação (opcional; invalida `ubuntu-ied-2` até recriar a PKI)

Terminal do host:

```bash
cd pki
./gerar_pki.sh --revogar ubuntu-ied-2
ID_AUT=$(python3 -c "import json,sys;print([n['node_id'] for n in json.load(open(sys.argv[1]))['topology']['nodes'] if n['name']=='autenticador-8021x'][0])" ~/GNS3/projects/subestacao_8021x/subestacao_8021x.gns3)
cp saida/nos/autenticador-8021x/crl.pem ~/GNS3/projects/subestacao_8021x/project-files/docker/$ID_AUT/etc/8021x/crl.pem
```

Console `autenticador-8021x`:

```bash
autenticador-ctl recarregar-crl
sleep 65
autenticador-ctl reautenticar
sleep 5
grep auth_rejeitada /var/log/8021x/eventos.jsonl | tail -n 3
```

Console `oraculo-1`:

```bash
python3 oraculo.py 192.168.10.12
```

Esperado: `auth_rejeitada` para `ubuntu-ied-2` com `certificado_revogado`; o Oráculo não alcança `192.168.10.12`.

## E3 — Certificado válido de OUTRO dispositivo usando o MAC de um IED: rejeitado pelo vínculo CN↔MAC

Console `atacante-1` (certificado válido `atacante-comprometido`, MAC do `ubuntu-ied-1`):

```bash
ip link set eth0 down; ip link set eth0 address 02:00:c0:a8:0a:0b; ip link set eth0 up
AUTH_8021X_TIMEOUT=15 8021x-supplicant start
ping -c 3 -W 2 192.168.10.12
8021x-supplicant stop
ip link set eth0 down; ip link set eth0 address 02:00:c0:a8:0a:28; ip link set eth0 up
```

Console `autenticador-8021x`:

```bash
grep mac_divergente /var/log/8021x/eventos.jsonl | tail -n 2
```

Esperado: o TLS é aceito (certificado válido), mas `auth_rejeitada` com `"cn": "atacante-comprometido"`, `"motivo": "mac_divergente"` e `detalhe` indicando o MAC esperado (`02:00:c0:a8:0a:28`); o `ping` falha; o par não entra no set `autorizados` (`autenticador-ctl estado`).

Coletar: linha do `eventos.jsonl`, `autenticador-ctl estado`.

## E4 — Atacante com certificado VÁLIDO e MAC próprio: autentica e consegue enviar GOOSE (limite do 802.1X)

Console `ids-1` (sem `--auth`; deixar rodando):

```bash
python3 ids.py --iface eth0 --log /tmp/alertas_e4.jsonl
```

Console `publicador-1` (publicação legítima assinada; baseline):

```bash
GOOSE_HMAC_KEY=chave-de-teste python3 goose_attack.py --leaked-key-env GOOSE_HMAC_KEY flood --iface eth0 --template molde.pcap --pps 2 --duration 10
```

Console `atacante-1`:

```bash
AUTH_8021X_TIMEOUT=30 8021x-supplicant start
python3 goose_attack.py masquerade --iface eth0 --template molde.pcap --occurrence 0 --src-mac 02:00:c0:a8:0a:28
```

Console `ids-1` (outra aba, enquanto o atacante envia):

```bash
tcpdump -nn -e -i eth0 -c 5 ether proto 0x88b8
```

Esperado: `auth_aceita` para `atacante-comprometido`; o GOOSE forjado **chega** (aparece no `tcpdump` com origem `02:00:c0:a8:0a:28`) — o 802.1X autenticou o dispositivo, não a mensagem. O IDS (sem `--auth`) alerta `masquerade` somente porque o MAC difere do baseline.

Variação E4b — frame com a origem do publicador, MESMO com certificado válido:

```bash
python3 goose_attack.py masquerade --iface eth0 --template molde.pcap --occurrence 0
```

Console `autenticador-8021x`:

```bash
grep quadro_descartado /var/log/8021x/eventos.jsonl | tail -n 3
```

Esperado: o frame com origem `00:30:a7:01:b3:16` é **descartado** pela porta do atacante (o par porta+MAC autenticado é `02:00:c0:a8:0a:28`); nenhum alerta novo no IDS.

Coletar: `/tmp/alertas_e4.jsonl`, saída do `tcpdump`, `auth_aceita` e `quadro_descartado` do `eventos.jsonl`.

## E5 — Defesa em profundidade: 802.1X + HMAC + IDS

Console `ids-1` (com HMAC; parar o IDS anterior com Ctrl+C):

```bash
GOOSE_HMAC_KEY=chave-de-teste python3 ids.py --iface eth0 --auth --log /tmp/alertas_e5.jsonl
```

Console `publicador-1` (baseline assinado):

```bash
GOOSE_HMAC_KEY=chave-de-teste python3 goose_attack.py --leaked-key-env GOOSE_HMAC_KEY flood --iface eth0 --template molde.pcap --pps 2 --duration 10
```

Console `atacante-1` (autenticado como no E4; três tentativas):

```bash
# (i) certificado válido, MAC próprio, SEM a chave HMAC
python3 goose_attack.py masquerade --iface eth0 --template molde.pcap --occurrence 0 --src-mac 02:00:c0:a8:0a:28
# (ii) com a chave HMAC vazada, MAC próprio
GOOSE_HMAC_KEY=chave-de-teste python3 goose_attack.py --leaked-key-env GOOSE_HMAC_KEY masquerade --iface eth0 --template molde.pcap --occurrence 0 --src-mac 02:00:c0:a8:0a:28
# (iii) com a chave HMAC vazada e a origem do publicador
GOOSE_HMAC_KEY=chave-de-teste python3 goose_attack.py --leaked-key-env GOOSE_HMAC_KEY masquerade --iface eth0 --template molde.pcap --occurrence 0
```

Console `ids-1` / `autenticador-8021x`:

```bash
cat /tmp/alertas_e5.jsonl
```

```bash
grep quadro_descartado /var/log/8021x/eventos.jsonl | tail -n 3
```

Esperado:

| Tentativa | Camada que barra |
|---|---|
| (i) sem chave | IDS `--auth`: `auth_fail` (frame sem HMAC válido) |
| (ii) com chave, MAC próprio | IDS: `masquerade` (MAC de origem diferente do baseline do `gocbRef`) |
| (iii) com chave, origem do publicador | 802.1X: `quadro_descartado` (par porta+MAC não autorizado); o IDS nem vê o frame |

Coletar: `/tmp/alertas_e5.jsonl`, `quadro_descartado` do `eventos.jsonl`, prints dos três consoles.

## Coleta final (terminal do host)

```bash
ID_AUT=$(python3 -c "import json,sys;print([n['node_id'] for n in json.load(open(sys.argv[1]))['topology']['nodes'] if n['name']=='autenticador-8021x'][0])" ~/GNS3/projects/subestacao_8021x/subestacao_8021x.gns3)
cp ~/GNS3/projects/subestacao_8021x/project-files/docker/$ID_AUT/var/log/8021x/eventos.jsonl ./eventos_5marco.jsonl
```

Evidências da validação local (sem GNS3): `autenticador-8021x/evidencias/`.
