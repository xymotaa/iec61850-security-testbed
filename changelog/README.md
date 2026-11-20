# changelog/

Registro do que já foi feito em relação ao artigo original e do que
falta, organizado pelos marcos de avaliação continuada da disciplina
Segurança em Redes de Computadores (ver cronograma em
`docs/SRC-Cap0-Apresentação da Disciplina-4.pdf`).

Artigo sendo reproduzido: Oliveira, L. H. V.; Gurjão, E. C.
*Analisador Automático de Segurança Cibernética para o Setor Elétrico.*
SBSeg 2025 — WTICG (`docs/36767-853-29863-1-10-20250831-2.pdf`).

**Vai apresentar/testar o projeto ao vivo?** Os comandos prontos pra
copiar/colar em cada console do GNS3 (Oráculo, ataques, IDS, geração de
topologia) estão em [`roteiro-demo.md`](roteiro-demo.md).

## Status atual (3º Marco — 05/10/2026, apresentado 20/10/2026)

O que o artigo original entregava, e onde o projeto está hoje:

| Etapa do artigo original | Status |
|---|---|
| Extração de SCD (IP, máscara, nome do IED) | ✅ Reproduzido e estendido (`extracao-scd/extrair_scd.py` também extrai blocos GOOSE/SV: `gocbRef`, `datSet`, MAC, APPID, VLAN) |
| Geração automática da topologia GNS3 a partir do SCD (Fig. 1 do artigo) | ✅ Fechado nesta entrega (`extracao-scd/gerar_topologia_gns3.py`) — antes a topologia era só montada manualmente |
| Topologia: 4 switches + 5 IEDs + Oráculo | ✅ Reproduzida (manualmente até aqui; agora também gerável automaticamente) |
| Oráculo: SR 1.3 (senha forte) + SR 1.7 (expiração) | ✅ Reproduzido e estendido para 8 critérios (SR 1.1, 1.3, 1.5, 1.7, 2.1, 3.1, 5.1, 7.1) |
| Relatório de conformidade via SSH | ✅ Reproduzido |
| "Trabalho futuro" do artigo: novos tipos de ataque | ✅ Estendido — 4 ataques GOOSE (flood, replay, masquerade, suppress) + IDS próprio (`ids-1`), com métricas de detecção |

Resultados já coletados (5 IEDs auditados, 5 cenários de ataque
testados, 0 falsos positivos) estão em
`docs/metodologia_proposta_gns3.md`.

## Status atual (4º Marco — 09/11/2026)

1. ✅ **`gerar_topologia_gns3.py` validado dentro do GNS3 de verdade.**
   Dois bugs reais foram encontrados e corrigidos nesse processo (ver
   commit `d898a34` e [`conteudo-apresentacao-4marco.md`](conteudo-apresentacao-4marco.md)):
   - `x`/`y` dos nós eram `float` (ex. `-530.0`); o schema do GNS3
     exige `integer` estrito — corrigido com `int(round(...))`.
   - Nome dos nós IED (`ied-<nome-do-SCD>`) não terminava em número,
     então o `entrypoint.sh` de `ubuntu-ied` (que deriva o IP do
     hostname, padrão `ubuntu-ied-N` → `192.168.10.1N`) não configurava
     nenhum IP — corrigido nomeando os nós sempre `ubuntu-ied-{N}`,
     mantendo nome/IP reais do SCD como metadado (`IED_NAME`,
     `IED_IP`) no ambiente do container.
   Depois das correções: projeto abre sem erro, `ubuntu-ied-1` pega IP
   automaticamente, `oraculo-1` audita via SSH com sucesso, e
   `atacante-1`/`ids-1` completam um ciclo de ataque (replay) e
   detecção real dentro dessa topologia.
2. ✅ **Extração rodada sobre um SCD real.** Usado
   `simpleIO_direct_control_goose.scd`, do repositório open-source
   `mz-automation/libiec61850` (GPL-3.0) — 1 IED real, 2 blocos GOOSE
   reais (`gcbEvents`, `gcbAnalogValues`) com MAC/APPID/VLAN. Pipeline
   completo testado ponta a ponta: SCD real → `dados_real.json` →
   `subestacao_real.gns3` → GNS3 real → Oráculo (3/12 critérios
   conformes, mesmo padrão do 3º Marco) → ataque replay → detecção
   pelo `ids-1`. Limitação assumida: esse SCD só descreve 1 IED (vs. 2
   do sintético usado antes) — ainda assim é dado real, não fictício.
3. ✅ **Campanha de testes do IDS com repetições.** Apresentada no 4º
   Marco com N=600 (100 repetições × 6 cenários), mas o
   `benchmark_ids.py` original **nunca foi versionado**; só os slides
   (`conteudo-apresentacao-4marco.md`, Bloco 3B) a registram. No 5º
   Marco foi reconstruída e reproduzida em `benchmark/` (ver abaixo).
4. ✅ **Layout do `.gns3` gerado** — não precisou de ajuste manual
   além do que já foi corrigido (bug de posição float); abriu
   legível no GNS3 real.

## Status atual (5º Marco — 23/11/2026, resultados finais)

Relatório consolidado: [`docs/resultados.md`](../docs/resultados.md).
Texto para os slides: [`conteudo-apresentacao-5marco.md`](conteudo-apresentacao-5marco.md).
Roteiro dos testes 802.1X: [`guia-testes-5marco.md`](guia-testes-5marco.md).

### Feito

| Item | Evidência |
|---|---|
| ✅ HMAC opt-in estilo IEC 62351-6 (**simulação**, não conforme) no IDS (`--auth`) e no atacante (`--leaked-key-env`) | `ids/goose_auth.py`, `atacante/goose_auth.py`, `ids/README.md`, `atacante/README.md` |
| ✅ Campanha offline reproduzida: N=100 por cenário × 6 cenários × 3 modos (sem HMAC, HMAC, chave vazada), IC95% de Wilson, semente 61850 | `benchmark/resultados/resumo.md`, `campanha_trials.csv` (1800 repetições), `benchmark/figuras/` |
| ✅ Sensibilidade do limiar de flooding (TPR × taxa de ataque; FPR do baseline) | `benchmark/resultados/sensibilidade_*.csv` |
| ✅ Custo do HMAC (microbenchmark de `sign`/`verify`, 20 000 chamadas) | `benchmark/resultados/latencia_hmac_micro.csv` |
| ✅ IEEE 802.1X EAP-TLS **real** (`hostapd` + `nftables`), vínculo CN↔MAC, CRL, supplicant nas 4 imagens | `autenticador-8021x/`, `pki/`, `extracao-scd/inventario_8021x.py` |
| ✅ Variante `--8021x` do gerador de topologia | `extracao-scd/gerar_topologia_gns3.py`, `extracao-scd/subestacao_8021x.gns3` |
| ✅ Validação do 802.1X em `netns`: 11 execuções registradas em 20/11/2026 (10 sem falha, 1 com 2 falhas) | `autenticador-8021x/evidencias/teste_netns-*.log` |
| ✅ Validação do 802.1X no **GNS3 real** (20/11/2026): base + cenários E0–E5, 1 execução cada | `autenticador-8021x/evidencias/gns3/RESULTADOS_GNS3.md` |
| ✅ Relatório final consolidado (Oráculo + ataques + benchmark + 802.1X + topologia, citando o SCD usado e as repetições) | `docs/resultados.md` |
| ✅ Seção de limitações e trabalhos futuros (proposto / reproduzido / estendido / novo / em aberto) | `docs/resultados.md`, seção 9 |
| ✅ Revisão dos READMEs (comandos, caminhos e flags conferidos) | READMEs da raiz e de `ids/`, `atacante/`, `extracao-scd/`, `pki/`, `autenticador-8021x/`, `benchmark/` |

### Continua pendente

- ⏳ **Resumo expandido em formato SBC** (`artigo/`): conduzido à parte;
  o estado do texto não foi verificado ao fechar este item do changelog.
- ⏳ Medição de overhead/latência de autenticação 802.1X no GNS3.
- ⏳ Repetições estatísticas no GNS3 (hoje, 1 execução por cenário).
- ⏳ E2b (revogação em operação) no GNS3 — só validada em `netns`.
- ⏳ Falha intermitente observada em 1 das 11 execuções de `teste_netns.sh`
  (etapa de reautenticação após queda de link); causa não investigada.
- ⏳ IEC 62351-6 conforme (gestão e rotação de chaves), MACsec (802.1AE),
  RADIUS externo, VLAN dinâmica e publicador comprometido — trabalho
  futuro, fora do escopo desta entrega.
