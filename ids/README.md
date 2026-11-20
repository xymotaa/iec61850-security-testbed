# ids-1 — Detector de Anomalias GOOSE

Detecta os 4 ataques da metodologia (Seção 4), usando um núcleo próprio
em Python (`ids_core.py`) em vez do Suricata, porque o suporte a
protocolos não-IP como GOOSE não é confiável na versão estável do
Suricata.

**Validado:** núcleo de detecção testado com 6 cenários sintéticos (zero
falso positivo em tráfego normal + mudança de estado legítima; os 4
ataques detectados corretamente) e em um teste ponta-a-ponta real:
tráfego legítimo capturado (mesmo pcap usado para validar o
`goose_frame.py`) + um pacote de masquerade gerado pelo próprio
`atacante/goose_attack.py`, injetado e corretamente identificado.

## Build

```bash
docker build -t ids:latest .
```

## Uso (dentro do container, no GNS3)

```bash
python3 ids.py --iface eth0
# ou, gravando os alertas num arquivo:
python3 ids.py --iface eth0 --log /tmp/alertas.jsonl
```

(sem `sudo` — o container já roda como root por padrão, e a imagem
nem instala `sudo`.)

Deixa rodando numa janela de console enquanto roda os ataques do
`atacante-1` em outra — os alertas aparecem em tempo real.

## Limiares (ajustáveis via linha de comando)

- `--flood-pps` (padrão 20): pacotes/segundo no mesmo `gocbRef` acima
  disso dispara alerta de flooding.
- `--suppression-jump` (padrão 50): salto de `stNum` maior que isso é
  tratado como suppression.
- `--auth` (desligado por padrão): verifica o HMAC de cada frame — ver
  "Autenticação opcional" abaixo.

## O que cada alerta significa

| Tipo | Como é detectado |
|---|---|
| `flood_start` | Taxa de pacotes/segundo, por `gocbRef`, cruzou o limiar (alerta uma vez, na borda de subida)|
| `flood_end` | Taxa voltou ao normal — inclui duração e pico de pps do episódio |
| `replay` | `(stNum, sqNum)` recebido é menor ou igual ao último já visto |
| `masquerade` | O MAC de origem muda para um `gocbRef` já conhecido |
| `suppression` | `stNum` salta um valor implausivelmente alto de uma vez |
| `auth_fail` | (só com `--auth`) o frame não tem HMAC ou o HMAC não confere; o frame é descartado sem alterar o estado do monitor |

## Autenticação opcional (simulação da ideia da IEC 62351-6)

Com `--auth`, o IDS exige que cada frame traga um HMAC-SHA256 calculado
sobre `gocbRef`, `stNum`, `sqNum`, `t` e `allData`, com uma chave por
`gocbRef` derivada de uma chave-mestra (`GOOSE_HMAC_KEY`; sem ela, usa a
chave de TESTE pública do código — nunca use chave real). O HMAC vai num
trailer após o APDU (sinalizado em `Reserved1`) e é comparado com
`hmac.compare_digest`. Implementação em `goose_auth.py`.

**Isto é uma SIMULAÇÃO da ideia da IEC 62351-6, não uma implementação
conforme**: não há distribuição/rotação de chaves, a codificação do
trailer é arbitrária e o HMAC não impede replay (um frame legítimo
reenviado continua válido — quem pega é a checagem de `(stNum, sqNum)`)
nem protege contra quem possui a chave. Sem `--auth`, nada muda.

Avaliação offline (TPR/FPR e latência com e sem HMAC): `benchmark/README.md`.

## Integração na topologia GNS3

Adicionar como novo nó Docker (mesmo processo do `atacante-1`), conectado
no mesmo switch dos IEDs que se quer monitorar — precisa estar no mesmo
domínio de broadcast, já que GOOSE é multicast de Camada 2.

## 802.1X opcional

`AUTH_8021X=1` liga o supplicant EAP-TLS com o certificado `ids-1`, para o IDS receber o GOOSE atrás do `autenticador-8021x`. Desligado por padrão. Ver `autenticador-8021x/README.md`.
