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
3. ⏳ **Campanha de testes do IDS com mais repetições — ainda não
   feita.** Os resultados seguem vindo de execuções pontuais de cada
   ataque (4/5 detecção, 0 falsos positivos), não de uma campanha
   estatística (múltiplas repetições por cenário, variação de
   parâmetros como `--pps` no flood ou `--jump` no suppress). Fica
   para o relatório final do 5º Marco.
4. ✅ **Layout do `.gns3` gerado** — não precisou de ajuste manual
   além do que já foi corrigido (bug de posição float); abriu
   legível no GNS3 real.

## O que falta — 5º Marco (23/11/2026, resultados finais)

1. **Resumo expandido em formato SBC**, via Overleaf, cobrindo
   motivação, problemática, metodologia, resultados e comparação
   explícita com o artigo original — ainda não iniciado no repositório
   (não há `.tex` nem link de Overleaf registrado).
2. **Consolidar os resultados finais** (Oráculo + ataques GOOSE +
   geração automática de topologia) num único relatório de resultados,
   já citando o SCD usado, a quantidade de repetições por teste e as
   métricas finais de detecção.
3. **Seção de limitações e trabalhos futuros própria**, distinguindo
   claramente o que o artigo original propôs, o que este projeto
   reproduziu, o que foi estendido além do artigo, e o que ainda fica
   em aberto (ex.: proteção criptográfica nativa IEC 62351-6 — citada
   como mitigação definitiva para o caso de masquerade não detectado
   em `docs/metodologia_proposta_gns3.md`).
4. Revisão final do README e dos READMEs de cada módulo para garantir
   que todos os comandos/caminhos citados continuam batendo com o
   estado real do repositório (ex.: este changelog já corrigiu
   referências desatualizadas a `docs/metodologia.md` e
   `docs/resultados.md` que não existiam mais).
