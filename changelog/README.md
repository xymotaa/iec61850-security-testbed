# changelog/

Registro do que já foi feito em relação ao artigo original e do que
falta, organizado pelos marcos de avaliação continuada da disciplina
Segurança em Redes de Computadores (ver cronograma em
`docs/SRC-Cap0-Apresentação da Disciplina-4.pdf`).

Artigo sendo reproduzido: Oliveira, L. H. V.; Gurjão, E. C.
*Analisador Automático de Segurança Cibernética para o Setor Elétrico.*
SBSeg 2025 — WTICG (`docs/36767-853-29863-1-10-20250831-2.pdf`).

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

## O que falta — 4º Marco (09/11/2026)

Lacunas identificadas que ainda não foram fechadas:

1. **Validar `gerar_topologia_gns3.py` dentro do GNS3 de verdade.**
   O script já foi testado e gera um `.gns3` estruturalmente válido
   (nós, links, IDs — validado programaticamente), mas ainda não foi
   aberto e executado dentro do GNS3 real neste ambiente. Precisa:
   abrir o `.gns3` gerado, confirmar que o GNS3 aceita o arquivo sem
   erros, que os templates Docker (`ubuntu-ied`, `oraculo`,
   `atacante`, `ids`) conectam corretamente nos nós, e que a rede
   funciona (IEDs pegam IP, GOOSE multicast circula) do mesmo jeito
   que na topologia montada manualmente.
2. **Rodar a extração sobre um SCD real de subestação.** Hoje só
   existe `exemplo_subestacao.scd`, sintético com 2 IEDs. Conseguir um
   SCD real (ou mais representativo) e extrair/gerar a topologia a
   partir dele é o que de fato fecha o ciclo do artigo original —
   ou, não sendo possível, documentar explicitamente essa limitação
   assumida no relatório.
3. **Campanha de testes do IDS com mais repetições.** Os resultados
   atuais (4/5 detecção, 0 falsos positivos) vêm de execuções pontuais
   de cada ataque, não de uma campanha estatística (múltiplas
   repetições por cenário, variação de parâmetros como `--pps` no
   flood ou `--jump` no suppress). Repetir cada teste algumas vezes
   fortalece a métrica para o relatório final.
4. **Ajustar o layout do `.gns3` gerado**, se necessário, depois de
   abrir no GNS3 (o script usa um layout automático simples em
   estrela/grade — normal precisar reposicionar nós manualmente para
   leitura).

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
