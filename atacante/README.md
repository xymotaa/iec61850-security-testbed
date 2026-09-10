# Ataque GOOSE — container `atacante-1` (Teste A–D da Seção 4)

Implementa os 4 testes de ataque propostos na metodologia:

| Comando | Teste | O que faz |
|---|---|---|
| `flood` | A — Flooding | Reenvia o molde em alta taxa, com stNum/sqNum/timestamp atualizados |
| `replay` | B — Replay | Reenvia o molde capturado sem nenhuma alteração |
| `masquerade` | C — Insertion/Masquerade | Inverte um valor booleano do dataset e ajusta stNum/sqNum/t, forjando uma mudança de estado |
| `suppress` | D — Suppression | Salta o stNum muito à frente para fazer o assinante descartar mensagens legítimas futuras |

**Validação feita:** o núcleo (`goose_frame.py`) foi testado contra uma
mensagem GOOSE real (relé SEL-351) — parse e reconstrução dão
**bytes idênticos** ao original, e os 4 ataques foram testados em modo
`--dry-run` (monta o pacote sem enviar). Isso já pode entrar no artigo
como validação da ferramenta, na Seção de Metodologia.

## 1. Build da imagem

```bash
docker build -t goose-attack:latest .
```

## 2. Integração no GNS3

1. Em **Edit → Preferences → Docker → Docker containers**, adicione um novo
   template apontando para a imagem `goose-attack:latest`.
2. Nas configurações avançadas do template, marque **"Extra capabilities"**
   incluindo `NET_ADMIN` e `NET_RAW` (necessário para `sendp`/`sniff` fazerem
   raw socket).
3. Arraste o novo nó `atacante-1` para a topologia e conecte na mesma
   `OpenvSwitch` onde já estão os `ubuntu-ied-N` (GOOSE é multicast de
   Camada 2 — só funciona se o atacante estiver no mesmo domínio de
   broadcast/VLAN dos IEDs alvo).

## 3. Uso (dentro do console do container, como root)

```bash
# 1) Capturar uma mensagem GOOSE legítima como "molde" (ex: 15s de escuta)
python3 goose_attack.py capture --iface eth0 --out molde.pcap --timeout 15

# 2) Teste A - Flooding
python3 goose_attack.py flood --iface eth0 --template molde.pcap --pps 2000 --duration 15

# 3) Teste B - Replay
python3 goose_attack.py replay --iface eth0 --template molde.pcap --delay 3

# 4) Teste C - Masquerade/Insertion (inverte o 1º valor booleano do dataset)
python3 goose_attack.py masquerade --iface eth0 --template molde.pcap --occurrence 0

# 5) Teste D - Suppression
python3 goose_attack.py suppress --iface eth0 --template molde.pcap --jump 1000
```

Use `--dry-run` antes de `capture`/etc. (ex: `python3 goose_attack.py --dry-run flood ...`)
para montar os pacotes sem enviar nada — útil pra validar fora do GNS3 primeiro.

## 4. O que medir em cada teste (para o relatório/artigo)

- **Flood:** taxa de perda/atraso das mensagens GOOSE legítimas dos IEDs
  reais durante o ataque (capturar com Wireshark em um `ubuntu-ied-N` e
  comparar `stNum`/timestamps recebidos vs. esperados).
- **Replay:** o assinante aceita a mensagem repetida (não deveria, mas
  GOOSE puro não tem proteção nativa contra isso)?
- **Masquerade:** o "IED" alvo reage ao valor forjado (ex.: LED de status,
  log de evento)? Esse é o ataque de maior impacto potencial.
- **Suppression:** mensagens legítimas enviadas pelo IED real após o
  ataque continuam sendo processadas, ou são descartadas por parecerem
  "antigas" (stNum menor que o forjado)?

Se o container `ids-1` (Suricata) estiver rodando, registrar também se
cada ataque gerou alerta — essa é a métrica de detecção da Seção 5 da
metodologia.

## 5. Limitações conhecidas

- `allData` é tratado como blob opaco (copiado do molde capturado): a
  ferramenta não recalcula toda a árvore MMS Data do zero, só localiza e
  inverte valores booleanos de 1 byte já existentes. Isso é suficiente
  para os 4 testes propostos e é, na prática, o mesmo que um atacante
  real faria (capturar e mutar, não reconstruir do zero).
- Cada IED tem seu próprio `gocbRef`/dataset — capture um molde por IED
  que você quiser atacar.
