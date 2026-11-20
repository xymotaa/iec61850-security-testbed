# artigo/ — Artigo do 5º Marco (SBC, português)

Título provisório: *Defesa em profundidade para GOOSE: limites de um IDS de estado, de uma mitigação criptográfica no estilo IEC 62351-6 e do controle de acesso IEEE 802.1X (EAP-TLS)*.
O fio central é: 802.1X controla quem entra; HMAC protege cada mensagem; IDS detecta anomalias — e o que cada camada NÃO resolve.

Arquivos:
- `main.tex` — artigo completo (TikZ embutido: arquitetura, máquina de estados, árvore de ataques, arquitetura 802.1X + fluxo de decisão de autorização).
- `referencias.bib` — referências (dados conferidos online em 20/11/2026; o que não foi confirmado está com `note = {VERIFICAR}`).
- `figuras/` — reservada para figuras `.tex`/imagens adicionais (vazia; os diagramas estão em `main.tex`).

## Como compilar

### Overleaf (recomendado)
1. Baixe o template oficial SBC (`sbc-template.zip`, SBC/Overleaf "SBC Conference Template") e suba o projeto com `sbc-template.sty` e `sbc.bst` ao lado do `main.tex`.
2. Suba também `main.tex` e `referencias.bib`.
3. Compilador: pdfLaTeX; `main.tex` como arquivo principal.
4. Os gráficos do benchmark são lidos de `../benchmark/figuras/*.pdf`. No Overleaf, crie a pasta `benchmark/figuras/` na raiz com os PDFs e coloque o `.tex` em `artigo/` (mantendo a estrutura), ou ajuste o caminho em `\figbench` no preâmbulo. Sem o arquivo, a figura vira uma caixa `PENDENTE` (a compilação não quebra).

### Local
```bash
cd artigo && latexmk -pdf main.tex
```
Se `sbc-template.sty` não estiver na pasta, `main.tex` usa um layout aproximado só para validar a compilação (aviso `sbc-template.sty nao encontrado`); o PDF final deve ser gerado com o template oficial.
Pacotes exigidos: `babel`, `tikz`, `booktabs`, `tabularx`, `xcolor` (todos TeX Live padrão).

**Estado da validação:** neste ambiente não há `pdflatex`/`latexmk`, então `main.tex` NÃO foi compilado. Só foi checado o balanceamento de chaves e de `\begin/\end`. Compile no Overleaf antes de confiar.

## Mudanças desta revisão (resultados reais do GNS3)

O 802.1X EAP-TLS foi validado no GNS3 real em 20/11/2026. Fonte única: `autenticador-8021x/evidencias/gns3/RESULTADOS_GNS3.md` e os arquivos ao lado (`eventos_gns3_20261120.jsonl`, `alertas_e*.jsonl`, `tcpdump_e4.txt`).

- `main.tex`: resumo/abstract, contribuições, variante `--8021x`, vínculo CN↔MAC, Seção "Validação do 802.1X: GNS3 real e netns", discussão, limitações (ix), (xiv), (xv), "O que foi proposto" e conclusão atualizados. A tabela `tab:gns3pend` foi removida; `tab:8021x` agora cobre base, E0, E1, E2, E3, E4, E4b, E5 (i)(ii)(iii) com a coluna "Ambiente" (GNS3 / netns); E2b, queda de link e CA falsa aparecem como só netns.
- Ressalvas preservadas: E3 mostra "AUTORIZADA" no supplicant mas a recusa vem do vínculo CN↔MAC (plano de dados); o contador do `nft` é a evidência confiável; 352→386 bytes (34 B) é inferência compatível com o trailer HMAC; E0 prova porta aberta pelo `ping`; cada cenário executado uma vez no GNS3 (sem repetições estatísticas); E2b e overhead de autenticação não medidos no GNS3.
- `esqueleto.md`: estrutura enxuta para o autor digitar o artigo.
- Não compilado (sem LaTeX). Conferido por script simples: chaves e `\begin/\end` balanceados, todos os `\ref` com `\label`, todas as `\cite` com entrada no `.bib`.

Números do 802.1X em netns conferidos nos logs: 11 execuções de `teste_netns.sh` em `evidencias/` = 8 com 30/0, 2 com 29/0 (roteiro anterior) e 1 com 28/2; `teste_imagens_clientes` = 16 verificações, 0 falhas. A frequência "1 em 6" do bug de correlação vem do README do autenticador, não dos logs; a causa do race do supplicant é hipótese.

## Pendências

Marcadas em vermelho no PDF (`\todo{...}`) e em laranja (`\verif`). O macro `\pend` continua definido, mas não é mais usado no texto.

Resultados: campanha reproduzida offline (`benchmark/resultados/`), N=100 por cenário e modo; Tabela 2 = campanha anterior do 4º Marco (script original não versionado); Tabela "Defesa em profundidade"; Tabela 802.1X = GNS3 + netns. Figuras (PDF): `tpr_por_cenario`, `latencia_por_cenario`, `sensibilidade_limiar`.

Pendências restantes:
- [ ] **Latência/overhead de autenticação em topologia real** (EAP-TLS): não medido em nenhum ambiente (`\todo` na Discussão).
- [ ] Não repetido no GNS3 (limitação, não bloqueio): campanha de HMAC (C1 sem/com HMAC/chave vazada), varredura do limiar, E2b, queda de link, CA falsa; cada cenário E0–E5 foi executado uma vez, sem repetições estatísticas.
- [ ] **Compilar no Overleaf** com o template SBC oficial (nada foi compilado). A figura TikZ do 802.1X nunca foi renderizada: confira sobreposição de nós (`\resizebox{\linewidth}{!}{...}`) e a nova tabela `tab:8021x` (5 colunas, `\scriptsize`), que pode ficar apertada.
- [ ] Confirmar a causa do race do supplicant (hoje só hipótese: EAPOL-Logoff atrasado de daemon antigo; sem captura de pacotes) e repetir `teste_netns.sh` mais vezes para quantificar a intermitência do bug de correlação (1/6 é amostra pequena).
- [ ] Citações: `ieee8021x` e `iec62351-6` passaram a ser citadas; conferir edição/ano no `.bib`. Não há referência para EAP-TLS (RFC 5216), `hostapd` ou `nftables`; adicionar se o professor/orientador quiser.
- [ ] Commitar os scripts de `benchmark/` e citar repositório/commit (hoje não commitados) em "Campanha reproduzida".
- [ ] Informar o modelo de CPU da máquina da campanha reproduzida (`execucao.json` guarda só Python e SO).
- [ ] Reconferir latências: valores absolutos variam entre execuções (e não são comparáveis com a campanha do 4º Marco); se rodar de novo, atualizar Tabela 4 e o texto (que usa só ordem de grandeza).
- [ ] Tabela ataque × norma: cláusulas de IEC 61850-8-1 e IEC 62351-6, SRs adicionais de IEC 62443-3-3 para L2 e papel exato do IEEE 802.1X estão `VERIFICAR` (o repositório só sustenta SR 3.1/5.1/7.1 do Oráculo, 4 ms, monotonicidade de stNum/sqNum e a menção a 62351-6/802.1X como mitigação).
- [ ] `VERIFICAR` na descrição do HMAC: relação exata da simulação com o mecanismo da IEC 62351-6 (a simulação NÃO é conforme: trailer 0xA0 arbitrário, sem gestão de chaves).
- [ ] Edição/ano das normas em `referencias.bib`; páginas do artigo SBSeg 2025; evento/editora do GOOSEIDRS (KIT) e venue do PowerDuck.
- [ ] Trabalhos relacionados: as frases da Seção 2 se baseiam apenas nos títulos; ler os artigos e comparar método/métricas.
- [ ] Autores: sobrenome de Matheus e Youri, afiliação completa e e-mails.
- [ ] Limite de páginas SBC (meta 6–8): conferir após compilar com o template oficial (o artigo cresceu bastante com o 802.1X: nova figura grande, 3 tabelas novas e mais texto; provável estouro). Se estourar, sugestão de cortes, em ordem: (1) Tabela de sensibilidade do limiar (manter só o texto/figura); (2) Tabela anterior do 4º Marco (resumir em uma frase, já que a reproduzida coincide); (3) (feito: a Tabela de pendências do GNS3 foi removida; se faltar espaço, enxugar as linhas só-netns da `tab:8021x`); (4) encurtar a lista de decisões de projeto do 802.1X; (5) mover limitações (xii)–(xv) para o repositório. NÃO cortar a tabela E0–E5, a figura 802.1X nem a tabela de camadas, que sustentam a tese.
Observações sobre a bibliografia: Hussain et al. (Scientific Reports) consta no Crossref como vol. 13, art. 1857, **2023** (o DOI `s41598-022-...` é de submissão em 2022); Auto-SGCR é de 2025; o artigo do SBSeg 2023 (`sol.sbc.org.br/.../27230`) tem DOI `10.5753/sbseg.2023.233109`. Falha de rede impediu abrir a página SOL do artigo SBSeg 2025 (o DOI foi apenas informado, não reconferido).
