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

## Mudanças do 802.1X (esta revisão)

Novo: subseção "Controle de acesso L2 com IEEE 802.1X (EAP-TLS)" (Seção 4), subseção de validação em netns (Seção 5), Tabela ataque × norma com a coluna 802.1X atualizada, discussão de defesa em profundidade, lições de engenharia, limitações (ix)–(xiv), conclusão e resumo/abstract.
Números do 802.1X conferidos nos logs: 11 execuções de `teste_netns.sh` em `evidencias/` = 8 com 30/0, 2 com 29/0 (roteiro anterior, sem a verificação "p5 nunca chegou a ser autorizado") e 1 com 28/2; `teste_imagens_clientes` = 16 verificações, 0 falhas (1 log). Atenção: o briefing falava em "11 execuções 30/0 + 1 com 28/2"; os logs não confirmam isso, e o artigo usa o que os logs mostram.
A frequência "1 em 6" do bug de correlação vem do README do autenticador, não dos logs; a causa do race do supplicant está marcada como hipótese.

## Pendências


Marcadas em vermelho no PDF (`\todo{...}`, `\pend`) e em laranja (`\verif`).

Resultados: preenchidos com os dados reais de `benchmark/resultados/` (campanha reproduzida offline, N=100 por cenário e modo; sensibilidade do limiar). Tabela 2 = campanha anterior do 4º Marco (rotulada como tal; o script original não foi versionado); Tabela 3 = campanha reproduzida nos 3 modos; Tabela 4 = C1 com HMAC e custo de latência; Tabela 5 = sensibilidade do limiar; Tabela "Defesa em profundidade" = camadas × o que controla/não resolve; Tabela 802.1X = cenários E0–E5 validados em netns (fonte: `autenticador-8021x/evidencias/`); Tabela de pendências do GNS3 (campos `\pend`). Figuras usadas (PDF): `tpr_por_cenario`, `latencia_por_cenario`, `sensibilidade_limiar` (a `custo_hmac` foi removida: o custo está na Tabela 4 e na Figura de latência).

Pendências restantes:
- [ ] **Validação em topologia GNS3 real** (`\todo` na Discussão): repetir C1 sem HMAC / com HMAC / chave vazada e a varredura do limiar no GNS3 e comparar com a campanha offline. Todos os resultados de HMAC e de limiar do artigo são offline.
- [ ] **Executar E0–E5 no GNS3** (`changelog/guia-testes-5marco.md`, topologia `subestacao_8021x`) e preencher a Tabela "Cenários a executar no GNS3" (campos `\pend`) com `eventos.jsonl`, alertas do IDS e `tcpdump`. Nada do GNS3 foi inventado. Isso inclui o E5 (802.1X + HMAC + IDS), que não tem evidência combinada em nenhum ambiente.
- [ ] **Latência/overhead de autenticação** em topologia real (não medido em lugar nenhum) e abrir o `.gns3` no GNS3 (nunca aberto).
- [ ] Confirmar a causa do race do supplicant (hoje só hipótese: EAPOL-Logoff atrasado de daemon antigo; sem captura de pacotes) e, se possível, repetir `teste_netns.sh` mais vezes para quantificar a intermitência do bug de correlação (1/6 é amostra pequena).
- [ ] Citações: `ieee8021x` e `iec62351-6` passaram a ser citadas; conferir edição/ano no `.bib`. Não há referência para EAP-TLS (RFC 5216), `hostapd` ou `nftables`; adicionar se o professor/orientador quiser.
- [ ] Commitar os scripts de `benchmark/` e citar repositório/commit (hoje não commitados) em "Campanha reproduzida".
- [ ] Informar o modelo de CPU da máquina da campanha reproduzida (`execucao.json` guarda só Python e SO).
- [ ] Reconferir latências: valores absolutos variam entre execuções (e não são comparáveis com a campanha do 4º Marco); se rodar de novo, atualizar Tabela 4 e o texto (que usa só ordem de grandeza).
- [ ] Tabela ataque × norma: cláusulas de IEC 61850-8-1 e IEC 62351-6, SRs adicionais de IEC 62443-3-3 para L2 e papel exato do IEEE 802.1X estão `VERIFICAR` (o repositório só sustenta SR 3.1/5.1/7.1 do Oráculo, 4 ms, monotonicidade de stNum/sqNum e a menção a 62351-6/802.1X como mitigação).
- [ ] `VERIFICAR` na descrição do HMAC: relação exata da simulação com o mecanismo da IEC 62351-6 (a simulação NÃO é conforme: trailer 0xA0 arbitrário, sem gestão de chaves).
- [ ] Edição/ano das normas em `referencias.bib`; páginas do artigo SBSeg 2025; evento/editora do GOOSEIDRS (KIT) e venue do PowerDuck.
- [ ] Trabalhos relacionados: as frases da Seção 2 se baseiam apenas nos títulos; ler os artigos e comparar método/métricas.
- [ ] Autores: sobrenome de Matheus e Youri, afiliação completa e e-mails.
- [ ] Limite de páginas SBC (meta 6–8): conferir após compilar com o template oficial (o artigo cresceu bastante com o 802.1X: nova figura grande, 3 tabelas novas e mais texto; provável estouro). Se estourar, sugestão de cortes, em ordem: (1) Tabela de sensibilidade do limiar (manter só o texto/figura); (2) Tabela anterior do 4º Marco (resumir em uma frase, já que a reproduzida coincide); (3) a Tabela de pendências do GNS3 vira só um `\todo`; (4) encurtar a lista de decisões de projeto do 802.1X; (5) mover limitações (xii)–(xiv) para o repositório. NÃO cortar a tabela E0–E5, a figura 802.1X nem a tabela de camadas, que sustentam a tese.
- [ ] Compilar: nada foi compilado (sem LaTeX aqui). Checados por script simples (não é compilação): chaves e `\begin/\end` balanceados, todos os `\ref` com `\label` (as figuras do benchmark têm o label dentro de `\figbench`), todas as `\cite` com entrada no `.bib`. A figura TikZ do 802.1X nunca foi renderizada: confira no Overleaf sobreposição de nós (ela usa `\resizebox{\linewidth}{!}{...}`).

Observações sobre a bibliografia: Hussain et al. (Scientific Reports) consta no Crossref como vol. 13, art. 1857, **2023** (o DOI `s41598-022-...` é de submissão em 2022); Auto-SGCR é de 2025; o artigo do SBSeg 2023 (`sol.sbc.org.br/.../27230`) tem DOI `10.5753/sbseg.2023.233109`. Falha de rede impediu abrir a página SOL do artigo SBSeg 2025 (o DOI foi apenas informado, não reconferido).
