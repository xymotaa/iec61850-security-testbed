# ids-1 — Detector de Anomalias GOOSE

Detecta os 4 ataques da metodologia (Seção 4), usando um núcleo próprio
em Python (`ids_core.py`) em vez do Suricata — ver `docs/metodologia.md`
para o porquê dessa troca (suporte a protocolos não-IP como GOOSE não é
confiável na versão estável do Suricata).

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
sudo python3 ids.py --iface eth0
# ou, gravando os alertas num arquivo:
sudo python3 ids.py --iface eth0 --log /tmp/alertas.jsonl
```

Deixa rodando numa janela de console enquanto roda os ataques do
`atacante-1` em outra — os alertas aparecem em tempo real.

## Limiares (ajustáveis via linha de comando)

- `--flood-pps` (padrão 20): pacotes/segundo no mesmo `gocbRef` acima
  disso dispara alerta de flooding.
- `--suppression-jump` (padrão 50): salto de `stNum` maior que isso é
  tratado como suppression.

## O que cada alerta significa

| Tipo | Como é detectado |

| `flood_start`|Taxa de pacotes/segundo, por `gocbRef`, cruzou o limiar (alerta uma vez, na borda de subida)|
| `flood_end` | Taxa voltou ao normal — inclui duração e pico de pps do episódio |
| `replay` | `(stNum, sqNum)` recebido é menor ou igual ao último já visto |
| `masquerade` | O MAC de origem muda para um `gocbRef` já conhecido |
| `suppression` | `stNum` salta um valor implausivelmente alto de uma vez |

## Integração na topologia GNS3

Adicionar como novo nó Docker (mesmo processo do `atacante-1`), conectado
no mesmo switch dos IEDs que se quer monitorar — precisa estar no mesmo
domínio de broadcast, já que GOOSE é multicast de Camada 2.
