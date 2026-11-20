# Resultados no GNS3 real — 802.1X (EAP-TLS) — 20/11/2026

Ambiente: GNS3 2.2.61, projeto `subestacao_8021x` (gerado por
`gerar_topologia_gns3.py dados.json --8021x`, a partir do SCD sintético de
2 IEDs em `extracao-scd/dados.json`), 7 nós Docker ligados direto ao
`autenticador-8021x` (hostapd wired, um processo por porta, nftables bridge).
PKI de laboratório (`pki/gerar_pki.sh`), certificados instalados por
`pki/instalar_no_gns3.py`. Roteiro: `changelog/guia-testes-5marco.md`.

Portas: eth0 `ubuntu-ied-1`, eth1 `ubuntu-ied-2`, eth2 `oraculo-1`,
eth3 `ids-1`, eth4 `publicador-1`, eth5 `atacante-1`.

Fonte dos eventos: `eventos_gns3_20261120.jsonl` (log do autenticador,
copiado do volume do nó). Saídas de console foram coladas pelo operador;
alertas do IDS e o `tcpdump` foram extraídos do `ids-1` com `docker cp`.

## Resumo por cenário

| Cenário | Camada que barra | Observado | Evidência |
|---|---|---|---|
| Base | — | 5 `auth_aceita` (ied-1, ied-2, oraculo-1, ids-1, publicador-1), nenhum para `atacante-1`; `ubuntu-ied-1`: PAE `AUTHENTICATED`, EAP-TLS (método 13); `ping` ied-1→ied-2: 3/3, RTT médio 0,519 ms | `eventos_gns3_20261120.jsonl` |
| E0 — sem 802.1X (`autenticador-ctl desativar`) | nenhuma | `ping` do atacante: 3/3, RTT médio 0,468 ms; C1 sem alerta no IDS | `alertas_e0.jsonl` (vazio) |
| E1 — sem certificado, MAC do publicador | 802.1X (nftables) | `ping`: 0/3, `Destination Host Unreachable`; `quadro_descartado` em `eth5` com MAC `00:30:a7:01:b3:16`, motivo `origem_nao_autorizada`; nenhum alerta no IDS | `alertas_e1.jsonl` (vazio), `eventos_gns3_20261120.jsonl` |
| E2 — certificado revogado | 802.1X (TLS + CRL) | supplicant: "porta NÃO autorizada após 15s"; `auth_rejeitada`, `cn=revogado-1`, serial `100B`, `certificado_revogado`; `ping` 0/3 | `eventos_gns3_20261120.jsonl` |
| E3 — certificado válido de outro nó com MAC do `ubuntu-ied-1` | 802.1X (vínculo CN↔MAC) | TLS aceito (supplicant imprime AUTORIZADA), mas `auth_rejeitada` `mac_divergente` (esperado `02:00:c0:a8:0a:28`); par fora de `autorizados`; `ping` 0/3 | `eventos_gns3_20261120.jsonl` |
| E4 — certificado válido, MAC próprio | IDS (só heurística de MAC) | autentica; frame GOOSE forjado chega ao `ids-1` (`tcpdump`: origem `02:00:c0:a8:0a:28`); alerta `MASQUERADE` | `tcpdump_e4.txt`, `alertas_e4.jsonl` |
| E4b — certificado válido, origem do publicador | 802.1X (par porta+MAC) | `nft list set descartados`: `eth5 . 00:30:a7:01:b3:16`, 5 pacotes, 1760 bytes | saída do `nft` (console) |
| E5 (i) — sem chave HMAC, MAC próprio | IDS `--auth` | `AUTH_FAIL` | `alertas_e5.jsonl` |
| E5 (ii) — chave vazada, MAC próprio | IDS (heurística de MAC) | `MASQUERADE` | `alertas_e5.jsonl` |
| E5 (iii) — chave vazada, origem do publicador | 802.1X (par porta+MAC) | nenhum alerta novo no IDS; `nft`: `eth5 . 00:30:a7:01:b3:16`, 5 pacotes, 1930 bytes | `alertas_e5.jsonl` (2 linhas), saída do `nft` (console) |

## Observações

- No E3 o supplicant do atacante reporta "porta AUTORIZADA": o hostapd
  aceitou o certificado no TLS. A recusa vem do vínculo CN↔MAC, que não
  insere o par no set `autorizados`; o descarte é imposto no plano de dados.
- E4b e E5 (iii): 352 bytes por frame no E4b (1760/5) e 386 no E5 (1930/5).
  A diferença de 34 bytes é compatível com o trailer do HMAC (tag `0xA0`,
  comprimento e 32 bytes). É uma inferência a partir dos contadores.
- O log `quadro_descartado` registra descartes em degraus de 5 pacotes; os
  contadores do `nft` são a evidência confiável dos descartes recentes
  (entradas expiram em 2 min).
- E0: o log do IDS vazio mostra ausência de alerta; a prova de que a porta
  estava aberta é o `ping`.
- Não executado no GNS3: E2b (revogação em operação), só validado em `netns`
  (`teste_netns.sh`). Não medimos overhead/latência de autenticação.
