# Guia de testes — 4º Marco

## 1. Subir topologia

GNS3: abrir projeto → **Ctrl+A** → **Start** → esperar ~10s.

Consoles: `ids-1`, `atacante-1`, `oraculo-1`.

| Nó | IP |
|---|---|
| `ubuntu-ied-1` .. `ubuntu-ied-5` | `192.168.10.11` .. `192.168.10.15` |
| `oraculo-1` | `192.168.10.20` |

## 2. Oráculo (console `oraculo-1`)

```bash
python3 oraculo.py 192.168.10.11
python3 oraculo.py 192.168.10.12
python3 oraculo.py 192.168.10.13
python3 oraculo.py 192.168.10.14
python3 oraculo.py 192.168.10.15
```

## 3. IDS (console `ids-1`)

```bash
python3 ids.py --iface eth0
```

## 4. Ataques (console `atacante-1`)

⚠️ Rodar o **replay primeiro, sempre** — é ele que estabelece a baseline
(MAC/stNum/sqNum) daquele `gocbRef` no `ids-1`. O `GooseMonitor` só
compara masquerade contra um MAC **já visto antes** no mesmo `gocbRef`;
se C1/C2 for o primeiro frame daquele `gocbRef` que o IDS processa,
não há nada pra comparar e o ataque passa sempre, mesmo com MAC
diferente (C2). Isso também derruba qualquer ataque se o MAC passado
em `--src-mac` estiver incompleto (o Scapy não valida e completa com
zeros silenciosamente — confira o MAC tem 6 pares de hex antes de
rodar).

```bash
# B — Replay (rodar primeiro: estabelece a baseline do gocbRef no IDS)
python3 goose_attack.py replay --iface eth0 --template molde.pcap --delay 3

# A — Flooding
python3 goose_attack.py flood --iface eth0 --template molde.pcap --pps 2000 --duration 15

# C1 — Masquerade, MAC clonado (não detectado)
python3 goose_attack.py masquerade --iface eth0 --template molde.pcap --occurrence 0

# C2 — Masquerade, MAC forjado (detectado)
python3 goose_attack.py masquerade --iface eth0 --template molde.pcap --occurrence 0 --src-mac de:ad:be:ef:00:99

# D — Suppression
python3 goose_attack.py suppress --iface eth0 --template molde.pcap --jump 1000
```

## 5. Extração + geração de topologia (terminal host)

```bash
cd extracao-scd
python3 extrair_scd.py exemplo_subestacao.scd --json dados.json
python3 gerar_topologia_gns3.py dados.json --out subestacao.gns3
```

## 6. SCD real (terminal host + GNS3, opcional)

```bash
cd extracao-scd
python3 extrair_scd.py scd_real_simpleIO.scd --json dados_real.json
python3 gerar_topologia_gns3.py dados_real.json --out subestacao_real.gns3
cp subestacao_real.gns3 ~/GNS3/projects/subestacao_real/subestacao_real.gns3
```

No console `ubuntu-ied-1` dessa topologia:
```bash
ip a
```

No console `oraculo-1`:
```bash
python3 oraculo.py 192.168.10.11
```

No console `atacante-1`:
```bash
python3 goose_attack.py replay --iface eth0 --template molde.pcap --delay 3
```
