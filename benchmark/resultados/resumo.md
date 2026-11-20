# Resumo da campanha offline (N=100 por cenário, semente 61850)


## Modo `sem_hmac`

| Cenário | Detecções | Taxa (IC95% Wilson) | Latência IDS (µs) | Latência HMAC verify (µs) | Alertas |
|---|---|---|---|---|---|
| T0_baseline | 0/100 | 0,0% FPR [0,0%; 3,7%] | 11,62 ± 1,68 | 0,00 ± 0,00 | - |
| A_flooding | 100/100 | 100,0% TPR [96,3%; 100,0%] | 7,24 ± 2,59 | 0,00 ± 0,00 | flood_start |
| B_replay | 100/100 | 100,0% TPR [96,3%; 100,0%] | 10,73 ± 5,59 | 0,00 ± 0,00 | replay |
| C1_masquerade_sofisticado | 0/100 | 0,0% TPR [0,0%; 3,7%] | 5,56 ± 3,78 | 0,00 ± 0,00 | - |
| C2_masquerade_ingenuo | 100/100 | 100,0% TPR [96,3%; 100,0%] | 7,20 ± 2,78 | 0,00 ± 0,00 | masquerade |
| D_suppression | 100/100 | 100,0% TPR [96,3%; 100,0%] | 7,50 ± 2,36 | 0,00 ± 0,00 | suppression |

## Modo `hmac`

| Cenário | Detecções | Taxa (IC95% Wilson) | Latência IDS (µs) | Latência HMAC verify (µs) | Alertas |
|---|---|---|---|---|---|
| T0_baseline | 0/100 | 0,0% FPR [0,0%; 3,7%] | 5,92 ± 0,59 | 11,39 ± 1,06 | - |
| A_flooding | 100/100 | 100,0% TPR [96,3%; 100,0%] | 5,82 ± 1,49 | 2,12 ± 0,86 | auth_fail;flood_start |
| B_replay | 100/100 | 100,0% TPR [96,3%; 100,0%] | 17,93 ± 7,07 | 15,70 ± 3,12 | replay |
| C1_masquerade_sofisticado | 100/100 | 100,0% TPR [96,3%; 100,0%] | 4,97 ± 3,40 | 2,76 ± 2,45 | auth_fail |
| C2_masquerade_ingenuo | 100/100 | 100,0% TPR [96,3%; 100,0%] | 4,57 ± 1,61 | 2,49 ± 0,81 | auth_fail |
| D_suppression | 100/100 | 100,0% TPR [96,3%; 100,0%] | 4,72 ± 3,14 | 2,38 ± 1,02 | auth_fail |

## Modo `hmac_chave_vazada`

| Cenário | Detecções | Taxa (IC95% Wilson) | Latência IDS (µs) | Latência HMAC verify (µs) | Alertas |
|---|---|---|---|---|---|
| T0_baseline | 0/100 | 0,0% FPR [0,0%; 3,7%] | 6,93 ± 0,79 | 13,61 ± 1,25 | - |
| A_flooding | 100/100 | 100,0% TPR [96,3%; 100,0%] | 10,36 ± 1,63 | 18,00 ± 2,97 | flood_start |
| B_replay | 100/100 | 100,0% TPR [96,3%; 100,0%] | 15,87 ± 4,05 | 16,68 ± 3,06 | replay |
| C1_masquerade_sofisticado | 0/100 | 0,0% TPR [0,0%; 3,7%] | 8,56 ± 0,62 | 16,22 ± 2,06 | - |
| C2_masquerade_ingenuo | 100/100 | 100,0% TPR [96,3%; 100,0%] | 10,63 ± 2,66 | 17,20 ± 3,82 | masquerade |
| D_suppression | 100/100 | 100,0% TPR [96,3%; 100,0%] | 16,74 ± 5,89 | 21,06 ± 6,80 | suppression |

## Microbenchmark do HMAC (por chamada)

| Operação | Média (µs) | DP | Mediana | P99 |
|---|---|---|---|---|
| sign | 12.08 | 18.16 | 11.04 | 26.26 |
| verify | 12.85 | 5.50 | 11.53 | 35.34 |
