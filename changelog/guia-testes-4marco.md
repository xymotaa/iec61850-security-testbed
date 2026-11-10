# Guia de testes — 4º Marco (apresentação ao vivo)

Checklist linear de tudo que pode ser testado/mostrado amanhã, na
ordem recomendada. Copie e cole — não precisa digitar nada de cabeça.
Cada comando diz **em qual console** rodar.

Demo principal: topologia **sintética (5 IEDs)**. A topologia com o
**SCD real (1 IED)** aparece só no final, como evidência adicional —
ver `conteudo-apresentacao-4marco.md`, Bloco 4, para o porquê dessa
escolha.

---

## 0. Antes de abrir o GNS3

Confirma que os templates Docker já estão registrados no GNS3
(`ubuntu-ied`, `oraculo`, `atacante`, `ids`) — se não tiver certeza,
ver `atacante/README.md`.

---

## 1. Subir a topologia principal (5 IEDs)

1. Abrir no GNS3: projeto da topologia sintética (`subestacao.gns3`
   gerado por `extracao-scd/gerar_topologia_gns3.py`, ou a topologia
   já montada manualmente — o que você já testou e validou).
2. Selecionar todos os nós (**Ctrl+A**) → **Start**.
3. Esperar ~10s (cada `entrypoint.sh` configura o próprio IP sozinho).
4. Abrir console de 3 nós, lado a lado:
   - `ids-1` (fica rodando o tempo todo)
   - `atacante-1` (dispara os ataques)
   - `oraculo-1` (roda a auditoria)

IPs fixos (não precisa configurar nada):

| Nó | IP |
|---|---|
| `ubuntu-ied-1` .. `ubuntu-ied-5` | `192.168.10.11` .. `192.168.10.15` |
| `oraculo-1` | `192.168.10.20` |

**Se der erro ao abrir o `.gns3`** (`Invalid data in topology file: ...
is not of type 'integer'`): é o Bug 1 que já corrigimos — confirme que
está usando a versão do `.gns3` gerada **depois** do commit `d898a34`
(`gerar_topologia_gns3.py` já corrigido). Regenere se necessário:
```bash
cd extracao-scd
python3 gerar_topologia_gns3.py dados.json --out subestacao.gns3
```

---

## 2. Oráculo — auditoria de conformidade (console do `oraculo-1`)

```bash
python3 oraculo.py 192.168.10.11
```

Repetir trocando o IP (`.12`, `.13`, `.14`, `.15`) pra mostrar que os 5
IEDs dão **o mesmo resultado** — é o achado de "frota homogênea"
(mesma imagem base = mesma vulnerabilidade em todos).

Se quiser passar usuário/senha manualmente (normalmente não precisa,
já vem embutido):
```bash
python3 oraculo.py 192.168.10.11 --user usuario_IED --password senha123
```

**Resultado esperado:** 8 SRs avaliados, **3/12 critérios conformes**
em todos os 5 IEDs. Lembrar de citar a correção metodológica sobre
`ucredit = -1` (ver `conteudo-apresentacao-4marco.md`, Bloco 2A) — o
artigo original classificou como "não definido", mas no PAM real
(`libpam-pwquality`) é cota mínima obrigatória.

---

## 3. IDS — deixar monitorando (console do `ids-1`)

**Rodar antes de qualquer ataque** (Parte 4), e deixar rodando durante
toda a demo:

```bash
python3 ids.py --iface eth0
```

Sem `sudo` — a imagem nem tem `sudo` instalado (dá `bash: sudo:
command not found` se tentar).

Para também salvar os alertas em arquivo (opcional):
```bash
python3 ids.py --iface eth0 --log /tmp/alertas.jsonl
```

`Ctrl+C` encerra de forma limpa quando terminar a demo.

---

## 4. Ataques GOOSE (console do `atacante-1`)

A imagem já vem com molde pronto (`molde.pcap`, GOOSE real de relé
SEL-351) — não precisa capturar tráfego ao vivo.

### Teste A — Flooding (DoS)
```bash
python3 goose_attack.py flood --iface eth0 --template molde.pcap --pps 2000 --duration 15
```
**Esperado no `ids-1`:** `flood_start` ao cruzar ~20 pkts/s, `flood_end` quando o envio parar.

### Teste B — Replay
```bash
python3 goose_attack.py replay --iface eth0 --template molde.pcap --delay 3
```
**Esperado no `ids-1`:** `replay` já no 2º envio (`(stNum, sqNum)` repetido).

### Teste C1 — Masquerade, atacante "sofisticado" (MAC clonado) — **rodar antes do C2**
```bash
python3 goose_attack.py masquerade --iface eth0 --template molde.pcap --occurrence 0
```
**Esperado no `ids-1`:** **nenhum alerta.** Esse é o achado central — deixar alguns segundos de silêncio visível antes de rodar o C2, pra reforçar o contraste.

### Teste C2 — Masquerade, atacante "ingênuo" (MAC forjado)
```bash
python3 goose_attack.py masquerade --iface eth0 --template molde.pcap --occurrence 0 --src-mac de:ad:be:ef:00:99
```
**Esperado no `ids-1`:** `masquerade` — "MAC mudou de X para Y".

### Teste D — Suppression
```bash
python3 goose_attack.py suppress --iface eth0 --template molde.pcap --jump 1000
```
**Esperado no `ids-1`:** `suppression` — salto de `stNum` acima do limiar (50).

### Validar sem enviar à rede (opcional, se quiser testar antes)
Prefixar qualquer comando acima com `--dry-run` logo depois de `goose_attack.py`:
```bash
python3 goose_attack.py --dry-run flood --iface eth0 --template molde.pcap --pps 2000 --duration 15
```

### Tabela-resumo pra falar durante a demo

| Teste | Alerta no `ids-1` |
|---|---|
| A — Flood | `flood_start` / `flood_end` |
| B — Replay | `replay` já no 2º envio |
| C1 — Masquerade (MAC igual) | **nenhum alerta** |
| C2 — Masquerade (MAC forjado) | `masquerade` |
| D — Suppression | `suppression` |

---

## 5. Extração de SCD + geração de topologia (terminal do host, fora do GNS3)

Mostra o fluxo completo do artigo original (Fig. 1): SCD → JSON →
`.gns3`.

```bash
cd extracao-scd
python3 extrair_scd.py exemplo_subestacao.scd --json dados.json
python3 gerar_topologia_gns3.py dados.json --out subestacao.gns3
```

---

## 6. SCD real — evidência adicional (Bloco 4 da apresentação)

Esta parte **não precisa ser repetida ao vivo** se o tempo for curto —
já está validada e documentada com prints da sessão anterior. Se
quiser mostrar mesmo assim, roda fora do GNS3 primeiro (host):

```bash
cd extracao-scd
python3 extrair_scd.py scd_real_simpleIO.scd --json dados_real.json
python3 gerar_topologia_gns3.py dados_real.json --out subestacao_real.gns3
```

Se for abrir no GNS3 de verdade:
```bash
cp subestacao_real.gns3 ~/GNS3/projects/subestacao_real/subestacao_real.gns3
```
Depois: **File → Open Project** no GNS3 → `subestacao_real`.

No console do `ubuntu-ied-1` dessa topologia (nome diferente da
principal, mas mesmo padrão `ubuntu-ied-N`):
```bash
ip a
```
Esperado: `192.168.10.11/24`.

No `oraculo-1` dessa topologia:
```bash
python3 oraculo.py 192.168.10.11
```
Esperado: mesmo padrão, 3/12 conformes.

**Se quiser repetir o ataque+detecção nessa topologia também** (já
validado hoje, resultado: replay detectado):
```bash
# console do atacante-1
python3 goose_attack.py replay --iface eth0 --template molde.pcap --delay 3
```

---

## Erros já conhecidos e como resolver

| Sintoma | Causa | Solução |
|---|---|---|
| `Invalid data in topology file: X.0 is not of type 'integer'` ao abrir `.gns3` | Bug 1 (posições float) — já corrigido no `gerar_topologia_gns3.py` atual | Regenerar o `.gns3` com o script atualizado (commit `d898a34` ou posterior) |
| IED não pega IP (`ip a` não mostra nada em `eth0`) | Bug 2 (nome de nó sem número no final) — já corrigido | Confirmar que o nó se chama `ubuntu-ied-N`, não `ied-<nome>` |
| `python3: command not found` | Rodou um script no console errado (ex. `ids.py` dentro do `ubuntu-ied`) | Cada script roda só no seu próprio container: `ids.py` → `ids-1`; `oraculo.py` → `oraculo-1`; `goose_attack.py` → `atacante-1` |
| `goose_attack.py replay: error: the following arguments are required: --iface, --template` | Comando chamado sem os argumentos obrigatórios | Sempre passar `--iface eth0 --template molde.pcap` |
| `bash: sudo: command not found` | A imagem não tem `sudo` instalado — e não precisa, containers já rodam como root | Rodar o comando direto, sem `sudo` |
