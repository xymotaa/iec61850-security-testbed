# Metodologia Proposta — Novos Testes de Segurança Cibernética em Ambiente GNS3 (extensão do artigo original)

> Correção de rota: mantém o **GNS3** (não NS-3). O documento anterior (`metodologia_proposta_ns3.md`) pode ser ignorado/apagado.

## 1. O que muda em relação ao artigo original

O artigo original já tinha a arquitetura certa para isso: GNS3 emula containers Docker com SO real, então dá pra rodar ferramentas de ataque/verificação de verdade dentro da topologia — foi exatamente isso que o "Oráculo" fez, só que limitado a **um único critério**: conformidade de política de senha (IEC 62443-3-3 SR 1.3 e SR 1.7).

O pedido do professor ("novos testes") se encaixa bem em duas frentes que aproveitam 100% da infraestrutura que vocês já construíram:

1. **Ampliar a conformidade normativa** do Oráculo para mais requisitos da IEC 62443-3-3 (hoje só cobre 2 de dezenas de SRs).
2. **Adicionar testes ativos de ataque/detecção** nas mensagens GOOSE/SV, algo que o artigo original não fez — e que é exatamente o tipo de "avaliação de vulnerabilidades" que a Introdução do artigo promete mas não entrega ainda.

Isso também fortalece o artigo: hoje ele testa política de senha (um controle administrativo/host), mas nunca testa o protocolo de comunicação em si (GOOSE/SV), que é o coração da IEC 61850 e o alvo real de ataques em subestações.

## 2. Pipeline (mantém a Fig. 1 do artigo original)

O pipeline não muda estruturalmente — só ganham dois módulos novos dentro do ambiente GNS3:

```
Subestação Real → Documentos SCL → Arquivo SCD
        ↓
[Script Python de Extração]  (igual ao original: IP, máscara, nome do IED)
        ↓
[Script Python de Modelagem] (igual ao original: gera .gns3 com switches/hosts/imagens Docker)
        ↓
[GNS3: topologia simulada]
        ├── ubuntu-ied-1..N (como já existe)
        ├── oraculo-1        (existente — expandir escopo, ver Seção 3)
        ├── atacante-1       (NOVO — container com toolkit de ataque GOOSE)
        └── ids-1            (NOVO — container com Suricata/Zeek/Snort)
```

## 3. Ampliação do Oráculo — mais SRs da IEC 62443-3-3

Hoje o relatório do Oráculo (Fig. 3 do artigo) cobre só SR 1.3 e SR 1.7. Sugestão de expansão, mantendo o mesmo formato de relatório "Conforme / Não conforme":

| SR | Nome | O que testar no IED simulado |
|---|---|---|
| SR 1.1 | Identificação e autenticação de usuário humano | Existe conta com credencial padrão/hardcoded? |
| SR 1.5 | Gerenciamento de autenticadores | Há rotação/expiração real ou senha estática desde o deploy? |
| SR 2.1 | Aplicação de autorização | Conta usada roda com privilégio mínimo ou root/admin sempre? |
| SR 3.1 | Integridade da comunicação | Mensagens GOOSE têm alguma verificação de integridade (ex: IEC 62351-6)? |
| SR 5.1 | Segmentação de rede | Há separação (VLAN/firewall) entre rede de processo (GOOSE/SV) e rede de estação/TI? |
| SR 7.1 | Disponibilidade de recursos | O IED simulado resiste a um flood de conexões/mensagens sem negar serviço? |

Isso já é, sozinho, um "novo teste" defensável para o professor: passa de 2 para 6+ critérios avaliados automaticamente.

## 4. Novos testes ativos — ataques ao protocolo GOOSE/SV

Aqui entra o container `atacante-1`, usando Scapy (mesma lib usada no precedente acadêmico "Geese", testado justamente em GNS3, e na toolkit aberta `goose-IEC61850-scapy` para crafting de pacotes GOOSE). Estrutura os testes pela taxonomia de ataques GOOSE usada na literatura (dataset PowerDuck):

### Teste A — Flooding (negação de serviço)
**Procedimento:** `atacante-1` envia um volume alto de mensagens GOOSE forjadas na rede.
**Métrica:** taxa de perda/atraso das mensagens legítimas entre IEDs reais; ponto de saturação da rede.

### Teste B — Replay
**Procedimento:** capturar (Wireshark/tcpdump dentro do container) uma sequência legítima de GOOSE e reenviá-la depois, com `stNum`/`sqNum` desatualizados.
**Métrica:** o assinante aceita a mensagem repetida como válida? (GOOSE não tem proteção nativa contra isso — é esperado que sim, a menos que IEC 62351 esteja implementado.)

### Teste C — Insertion / Masquerade (falsificação)
**Procedimento:** `atacante-1` forja uma mensagem GOOSE se passando por um IED legítimo (mesmo `GoCBRef`/MAC multicast), com dado de estado divergente (ex: simular um comando de abertura de disjuntor).
**Métrica:** o "IED" alvo processa o comando falso? Esse é o ataque mais crítico da literatura (tem potencial de causar ação física indevida).

### Teste D — Suppression
**Procedimento:** enviar mensagens com número de sequência artificialmente alto para forçar os assinantes a descartar mensagens legítimas subsequentes.
**Métrica:** mensagens legítimas passam a ser ignoradas após o ataque?

## 5. Módulo de Detecção — container `ids-1`

Novo módulo: um container com Suricata (ou Zeek/Snort) monitorando a rede simulada, com regras específicas para tráfego GOOSE/SV anômalo (há precedente na literatura de usar Snort para detectar ataques GOOSE em testbeds híbridos RTDS).

**Métrica de sucesso:** taxa de detecção por tipo de ataque (A–D acima), taxa de falso positivo, e tempo entre início do ataque e alerta gerado.

Isso fecha o ciclo do artigo: **ataque simulado → efeito medido no protocolo → detecção (ou não) pelo IDS → relatório automatizado**, que é uma contribuição bem mais completa do que só "verificar política de senha".

## 6. Relatório final (Oráculo expandido)

Mantém o mesmo estilo visual da Fig. 3 original, mas agora com três blocos:
1. Conformidade IEC 62443-3-3 (6 SRs, Seção 3)
2. Resultado dos testes de ataque A–D (impacto: sim/não, métricas de rede)
3. Resultado da detecção pelo IDS (detectado: sim/não, tempo de resposta)

## 7. Ferramentas a adicionar no ambiente GNS3 (containers Docker novos)

- `atacante-1`: Python + Scapy + a lib `goose-IEC61850-scapy` (ou construir manualmente os frames GOOSE com Scapy, seguindo a estrutura do protocolo).
- `ids-1`: Suricata (mais leve de configurar que Zeek para um primeiro teste) com regras customizadas para o padrão de tráfego GOOSE (multicast, EtherType 0x88B8).
- Continua tudo dentro do GNS3, sem precisar trocar de ferramenta de simulação.

## 8. Referências novas a incluir na bibliografia

- Geese: A Traffic Generator for Performance and Security Evaluation of IEC 61850 Networks — testbed em GNS3 + Scapy, testou ataques Bad ACK-Reset e fragmentação de pacotes. Referência mais próxima do que vocês já fizeram.
- `goose-IEC61850-scapy` (GitHub, associado a paper do IEEE SmartGridComm) — toolkit para crafting/decoding de GOOSE com Scapy.
- PowerDuck: A GOOSE Data Set of Cyberattacks in Substations — taxonomia de ataques (replay, insertion, suppression, flooding) usada para estruturar a Seção 4.
- Trabalho com RTDS + Snort + "sequence content resolver" — precedente de uso de IDS (Snort) para detectar/mitigar ataques GOOSE, referência para a Seção 5.

## 9. Próximos passos possíveis

- Escrever o código Python/Scapy para gerar um frame GOOSE válido (Teste A ou C) a partir dos dados já extraídos do SCD.
- Escrever as regras Suricata para detectar tráfego GOOSE anômalo.
- Redigir a nova Seção 5 (Metodologia) e 5.2 (Resultados) do artigo com base neste documento.

Me diz qual desses três você quer que eu faça primeiro.
