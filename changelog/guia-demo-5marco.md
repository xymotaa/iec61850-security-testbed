# Guia de demo: 5º Marco (rápido, para mostrar ao vivo)

Versão **curta** do [`guia-testes-5marco.md`](guia-testes-5marco.md) (que tem todos os cenários E0 a E5 e a coleta de evidências). Use este se o professor pedir para ver funcionando. Os comandos são os mesmos já validados no GNS3 em 20/11/2026.

| Modo | Cenários | Tempo |
|---|---|---|
| **Mínimo** | E1 → E4 | ≈2 min |
| **Completo** | E1 → E4 → E4b (e E0 só como evidência gravada) | ≈4 min |

**Por que a ordem E1 → E4 e não E0 primeiro:** o E0 exige desativar o 802.1X e depois religar o *supplicant* em cada nó (1 min de bastidor). Para a demo, mostre o E0 pela evidência pronta (`autenticador-8021x/evidencias/gns3/alertas_e0.jsonl`: vazio, o IDS não alertou o C1) e rode ao vivo só o que mostra o 802.1X agindo.

**Valores:** `MAC_PUBLICADOR` = `00:30:a7:01:b3:16`; `MAC_ATACANTE` = `02:00:c0:a8:0a:28`; `ubuntu-ied-2` = `192.168.10.12`; chave HMAC de teste = `chave-de-teste` (pública, só de laboratório).

---

## Antes (≈10 min antes de começar)

1. GNS3: abrir `subestacao_8021x` → **Ctrl+A** → **Start** → esperar ~30 s.
2. Abrir os consoles lado a lado: `autenticador-8021x`, `ids-1`, `publicador-1`, `atacante-1`.
3. No `autenticador-8021x`, conferir a base:

```bash
autenticador-ctl estado
grep auth_aceita /var/log/8021x/eventos.jsonl
```

   Esperado: `auth_aceita` para `ubuntu-ied-1`, `ubuntu-ied-2`, `oraculo-1`, `ids-1` e `publicador-1`; **nenhum** para `atacante-1`.
4. No `ids-1`, deixar o IDS rodando **durante toda a demo** (sem `--auth`):

```bash
python3 ids.py --iface eth0 --log /tmp/alertas_demo.jsonl
```

5. Conferir que o `atacante-1` está no MAC próprio (`ip link show eth0` → `02:00:c0:a8:0a:28`) e com o *supplicant* desligado.

Se algum item falhar, vá direto ao **Plano B**.

---

## E1: atacante SEM certificado e com o MAC clonado do publicador (≈1 min)

**Fala:** "Este é o C1, o ataque que o IDS não via. Agora a rede tem 802.1X, e o atacante não tem certificado."

`publicador-1` (cria a referência do `gocbRef` no IDS):

```bash
python3 goose_attack.py replay --iface eth0 --template molde.pcap --delay 3
```

`atacante-1` (clona o MAC do publicador e tenta o masquerade):

```bash
ip link set eth0 down; ip link set eth0 address 00:30:a7:01:b3:16; ip link set eth0 up
python3 goose_attack.py masquerade --iface eth0 --template molde.pcap --occurrence 0
ping -c 3 -W 2 192.168.10.12
```

`autenticador-8021x`:

```bash
nft list set bridge acesso8021x descartados
grep quadro_descartado /var/log/8021x/eventos.jsonl | tail -n 3
```

**Esperado:**
- O `ping` falha (0/3).
- O par (porta do atacante, `00:30:a7:01:b3:16`) aparece em `descartados` com contador > 0.
- O console do `ids-1` **não mostra alerta nenhum**: o quadro foi barrado antes de chegar.

**Dizer:** "Quem barrou foi o 802.1X, não o IDS. O mesmo clone de MAC que passava sem alerta agora é descartado na porta."

**Restaurar o MAC antes do próximo cenário** (`atacante-1`):

```bash
ip link set eth0 down; ip link set eth0 address 02:00:c0:a8:0a:28; ip link set eth0 up
```

---

## E4: certificado VÁLIDO e MAC próprio (≈1 min 30 s)

**Fala:** "Agora o atacante é um nó comprometido: tem um certificado válido. O 802.1X vai autenticá-lo. O que acontece com a mensagem?"

`publicador-1` (baseline assinado):

```bash
GOOSE_HMAC_KEY=chave-de-teste python3 goose_attack.py --leaked-key-env GOOSE_HMAC_KEY flood --iface eth0 --template molde.pcap --pps 2 --duration 10
```

`atacante-1`:

```bash
AUTH_8021X_TIMEOUT=30 8021x-supplicant start
python3 goose_attack.py masquerade --iface eth0 --template molde.pcap --occurrence 0 --src-mac 02:00:c0:a8:0a:28
```

`autenticador-8021x`:

```bash
grep auth_aceita /var/log/8021x/eventos.jsonl | tail -n 2
```

**Esperado:**
- `auth_aceita` para `atacante-comprometido`.
- No console do `ids-1`, aparece o alerta `MASQUERADE` (o MAC de origem difere do baseline do `gocbRef`).

**Dizer:** "O 802.1X autenticou o dispositivo, não a mensagem: o GOOSE forjado chegou. Só o IDS alertou, e apenas porque o MAC é diferente. Se o atacante usasse o MAC do publicador, o IDS não veria, mas o 802.1X segura o par porta e MAC."

---

## E4b: mesmo com certificado, MAC do publicador (≈30 s, opcional)

`atacante-1`:

```bash
python3 goose_attack.py masquerade --iface eth0 --template molde.pcap --occurrence 0
```

`autenticador-8021x`:

```bash
nft list set bridge acesso8021x descartados
```

**Esperado:** o par (porta do atacante, `00:30:a7:01:b3:16`) em `descartados` com contador > 0; **nenhum alerta novo** no IDS.

**Dizer:** "Mesmo com certificado válido, o 802.1X só aceita o MAC ligado àquele certificado. Clonar o MAC do publicador não funciona."

---

## Depois (se for repetir)

`atacante-1`:

```bash
8021x-supplicant stop
ip link set eth0 down; ip link set eth0 address 02:00:c0:a8:0a:28; ip link set eth0 up
```

Reiniciar o IDS (Ctrl+C e subir de novo) se quiser um estado limpo.

---

## Plano B 1: sem GNS3 (evidências prontas)

Mostre os arquivos de `autenticador-8021x/evidencias/gns3/`:
- `RESULTADOS_GNS3.md`: tabela E0 a E5 com o que foi observado em 20/11/2026;
- `alertas_e0.jsonl` (vazio: o C1 passou), `alertas_e4.jsonl` (`masquerade`), `alertas_e5.jsonl` (`auth_fail` e `masquerade`);
- `eventos_gns3_20261120.jsonl` (`auth_aceita`, `auth_rejeitada`, `quadro_descartado`) e `tcpdump_e4.txt`.

Diga que cada cenário foi executado **uma vez** e que E2, E3 e E4b não tinham o IDS em execução.

## Plano B 2: campanha *offline* ao vivo (≈22 s, sem GNS3)

No terminal do host, na pasta `benchmark/` (grava em `/tmp`, não altera os resultados do repositório):

```bash
.venv/bin/python benchmark_ids.py --trials 20 --saida /tmp/demo_offline
sed -n 1,25p /tmp/demo_offline/resumo.md
```

Com 20 repetições por cenário, o resultado qualitativo é o mesmo da campanha de 100: o **C1 sai 0/20 sem HMAC**, 20/20 com HMAC e sem a chave, e 0/20 com a chave vazada. Os números do artigo (100 repetições) estão em `benchmark/resultados/resumo.md`.

---

## Se algo der errado

| Sintoma | O que fazer |
|---|---|
| `auth_aceita` não aparece para um nó | Esperar mais 30 s; no nó, `8021x-supplicant status`. Se persistir, `8021x-supplicant stop` e `start`. |
| O *supplicant* do atacante fica `Unauthorized` no E4 | Repetir com `AUTH_8021X_TIMEOUT=30`. Conferir o MAC: precisa ser `02:00:c0:a8:0a:28` (certificado `atacante-comprometido`). |
| O IDS não alerta no E4 | Conferir que o baseline do `publicador-1` foi enviado **antes** e que o IDS está em `eth0`. |
| O `ping` do E1 passa | O 802.1X pode estar desativado (resto do E0): no `autenticador-8021x`, `autenticador-ctl ativar` e `8021x-supplicant start` nos nós legítimos. |
| O console fecha ao abrir | Repetir o duplo clique; se o terminal abrir e fechar, abrir o console pelo menu do nó. |

**Não afirmar durante a demo:** que o HMAC é a IEC 62351-6; que o resultado vale para uma subestação real; qualquer número de latência do EAP-TLS (não foi medido).
