# artigo/ — Artigo do 5º Marco (SBC, português)

Título provisório: *Defesa em profundidade para GOOSE: limites de um IDS de estado, de uma mitigação criptográfica no estilo IEC 62351-6 e do controle de acesso IEEE 802.1X (EAP-TLS)*.
O fio central é: 802.1X controla quem entra; HMAC protege cada mensagem; IDS detecta anomalias — e o que cada camada NÃO resolve.

Arquivos:
- `main.tex` — artigo completo (TikZ embutido: arquitetura, máquina de estados, árvore de ataques, arquitetura 802.1X + fluxo de decisão de autorização). Macros: `\dd` (dois traços em flags, ex. `\texttt{\dd{}8021x}`), `\paragraph` redefinido (título em negrito na linha), `\figbench[largura]{pdf}{legenda}{rótulo}`.
- `referencias.bib` — referências (dados conferidos online em 20/11/2026; o que não foi confirmado está com `note = {VERIFICAR}`).
- `figuras/` — PDFs dos gráficos e da matriz de camadas; PNGs de evidência do GNS3 (não usados no artigo desde a revisão de formatação, mantidos como evidência).
- `overleaf-upload/` e `overleaf-upload.zip` — pacote para o Overleaf (main.tex, referencias.bib, sbc-template.sty, sbc.bst, figuras/ só com as 4 imagens usadas). `overleaf-upload-nao-usados/` guarda PNGs que saíram do pacote.

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

**Estado da validação:** compilado de verdade (pdflatex + bibtex, TeX Live 2026 em Docker) com `sbc-template.sty` e `sbc.bst`: **13 páginas** (A4, 12 pt), 0 erros, 0 overfull, 13 underfull (todos de parágrafos/listas, inofensivos), sem citação com `?`. O PDF compilado está em `main.pdf`. Limite de páginas da conferência: desconhecido (meta usada: 10 a 12; ficou em 13, ~12,8 de conteúdo).

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

## Figuras (inventário)

| Figura | Arquivo | Origem |
|---|---|---|
| Gráficos do benchmark (TPR, latência, sensibilidade) | `figuras/tpr_por_cenario.pdf`, `latencia_por_cenario.pdf`, `sensibilidade_limiar.pdf` | cópia de `benchmark/figuras/` (gerados por `benchmark/gerar_graficos.py`) |
| Camada que barra cada cenário (E0–E5) | `figuras/camadas_por_cenario.pdf` | `figuras/gerar_figuras_gns3.py` (dados de `autenticador-8021x/evidencias/gns3/RESULTADOS_GNS3.md`) |
| Topologia `subestacao_8021x` no GNS3 | `figuras/gns3_topologia_8021x.png` | print real do GNS3 (20/11/2026), recortado (aviso do xterm removido) |
| Evidência do E1 (consoles do atacante e do autenticador) | `figuras/gns3_e1_atacante.png`, `gns3_e1_autenticador.png` | prints reais, recortados por `gerar_figuras_gns3.py` a partir dos `*_full.png` |
| Diagramas (arquitetura, árvore de ataques, máquina de estados, 802.1X) | TikZ no próprio `main.tex` | — |

Para regerar: `benchmark/.venv/bin/python artigo/figuras/gerar_figuras_gns3.py`.
No Overleaf, suba `main.tex`, `referencias.bib`, `sbc-template.sty`, `sbc.bst` e a pasta `figuras/`.


## Revisão de formatação (compilação real)

Problemas do PDF anterior (24 páginas) e o que foi feito:
- Páginas: 24 -> 13. `\raggedbottom` (o `\flushbottom` do modelo abria buracos), floats `[!htb]` e menores, `\paragraph` sem espaço vertical, `microtype` não usado.
- Erros: `\text` sem `amsmath` (3 "Undefined control sequence" e o `\'` em modo matemático): `amsmath` carregado e `\mathrm` nas fórmulas.
- Flags: macro `\dd` (`--8021x`, `--auth`, `--privileged` saem com dois traços).
- Bibliografia: normas e libiec61850 com `year = {s.d.}` e autor institucional (`{{IEC}}`, `{{IEEE}}`, `{{MZ Automation}}`), mantendo `note = {VERIFICAR}`; nenhuma citação sai com "?" ou sem autor.
- TikZ: árvore de ataques (rótulos em 3 linhas, espaçamento 2,95 cm) e máquina de estados (alertas em linha, setas pelo topo) sem sobreposição, conferidos no PDF renderizado.
- Matriz de camadas (fig. 8): `gerar_figuras_gns3.py` corrigido de verdade (coluna "Frame passou" mostra o texto "passou"); fonte maior; PDF/PNG regenerados.
- Fig. do E1: os dois PNGs de console foram trocados por transcrição em `verbatim` (trechos fiéis, prompts omitidos, rotulada como transcrição).
- Tabelas: todas com <= 5 colunas, legenda antes, colunas `L{}`/`Y` (raggedright) sem overfull. Ataque x norma: Ataque | Propriedade | Requisito/norma | Camada. E0-E5: Cenário | Ambiente | Camada que barra | Resultado.

### O que foi cortado (e onde está agora)
1. Tabela de sensibilidade do limiar: removida (texto e Fig. 7 mantidos; números completos em `benchmark/resultados/`).
2. Tabela da campanha anterior do 4º Marco: removida; vira 3 frases na Seção 6.2 (400/500, C1 0/100, T0 sem falso positivo) e a coincidência com a reprodução offline.
3. Tabela de latência/HMAC (`tab:hmac`): removida; as médias de `verify`, o microbenchmark e os IC de Wilson estão no texto (6.3). A Fig. 6 (latência) foi mantida.
4. Decisões de projeto do 802.1X: 5 bullets curtos.
5. Limitações: de 15 itens para 5 grupos; os detalhes finos permanecem em `README.md`/`docs/resultados.md` do repositório.
6. Repetições do resultado E4/E5 (resumo, resultados, discussão, conclusão): detalhe só na Seção 6.5; nas demais, uma frase.
7. Figura da topologia GNS3 (PNG) removida do artigo por falta de espaço (não agrega dado novo); a linha "Base" da tabela E0-E5 foi fundida à linha E0; a descrição da "Variante com 802.1X" foi fundida à Seção 5.3.
Mantidos: tabela E0-E5, fig./diagrama 802.1X, tabela de defesa em profundidade, matriz de camadas, gráficos TPR e latência, quadro proposto/reproduzido/estendido/novo/em aberto e as ressalvas essenciais.

### Pendências atuais (revisão humana)
- Autores (sobrenomes de Matheus e Youri, afiliação, e-mails), edição/ano das normas, venue/páginas das referências (`VERIFICAR`), cláusulas na tabela ataque x norma, relação exata do HMAC com a IEC 62351-6, trabalhos relacionados (só descrição de uma frase), repositório/commit e CPU da campanha, limite de páginas da conferência.
- Latência e sobrecarga de autenticação (EAP-TLS) não medidas; cada cenário do GNS3 foi executado uma vez; campanha HMAC/limiar só offline; causa do race do supplicant é hipótese.
- Conferir no Overleaf (o PDF aqui foi gerado com TeX Live 2026 local; diferenças de versão podem mudar quebras de página).
