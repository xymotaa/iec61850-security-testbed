# Esqueleto do artigo (SBC, PT-BR) — para digitar

Fonte dos números: `main.tex` (tabelas por `\label`), `benchmark/resultados/*.csv`, `autenticador-8021x/evidencias/gns3/RESULTADOS_GNS3.md` (abrev. **GNS3.md**). Tudo abaixo é o que já está validado; nada foi compilado.

## Pedidos do professor → seção → material

| Pedido | Seção | Material |
|---|---|---|
| Técnicas | 5 | IDS de estado (fig `fig:estados`), HMAC por quadro, 802.1X EAP-TLS (fig `fig:arq8021x`) |
| Análises | 6, 7 | tab `tab:anterior`, `tab:reproduzida`, `tab:limiar`; `benchmark/figuras/*.pdf` |
| Normas | 2, 6 | tab `tab:normas` (células `\verif` = conferir antes de citar) |
| Modificações | 5 | HMAC (`ids/goose_auth.py`), `--8021x` no gerador, inventário CN→MAC |
| Complementares | 5, 7 | sensibilidade do limiar; defesa em profundidade (tab `tab:camadas`) |
| Cenários novos | 5, 6 | C1 com HMAC / chave vazada; E0–E5 (GNS3.md; tab `tab:8021x`) |
| Tabelas | 6 | `tab:anterior`, `tab:reproduzida`, `tab:hmac`, `tab:limiar`, `tab:8021x`, `tab:camadas` |
| Gráficos | 6 | `benchmark/figuras/tpr_por_cenario.pdf`, `latencia_por_cenario.pdf`, `sensibilidade_limiar.pdf` (há também `.png`) |
| Casos de uso | 4 | CU1 (abertura indevida), CU2 (suppression), CU3 (flooding) em `main.tex` §4 |
| Diagramas | 3, 4, 5 | TikZ em `main.tex`: `fig:arquitetura`, `fig:arvore`, `fig:estados`, `fig:arq8021x` |

## Resumo / Abstract
- Diz: GOOSE sem autenticação; até onde IDS passivo, HMAC e 802.1X protegem, e o que cada um não resolve.
- Pontos: IDS 100% em 4 ataques, 0% no C1; HMAC leva C1 a 100%, cai com chave vazada; 802.1X autentica o dispositivo, não a mensagem; HMAC simulado, não conforme à 62351-6.
- Reaproveitar: texto do `\begin{abstract}`/`resumo` em `main.tex` (encurtar).
- Números: C1 0/100→100/100, IC95% Wilson 96,3–100% (`campanha_resumo.csv`); 600 execuções do 4º Marco (`tab:anterior`); GNS3 E0–E5, cada um 1 vez (GNS3.md).

## 1 Introdução
- Diz: GOOSE (EtherType 0x88B8, <4 ms) sem autenticação; lacuna: o que um IDS de estado detecta e o que falta (quem entra, qual mensagem).
- Pontos: contexto OT/IT; trabalho base (Oliveira e Gurjão: SCL→GNS3, SSH/62443); pergunta de pesquisa; contribuições (i)–(vii).
- Reaproveitar: `main.tex` §1 (problema, pergunta, contribuições).
- Números: limite 4 ms (norma IEC 61850; `\verif` cláusula).

## 2 Fundamentação e relacionados
- Diz: semântica stNum/sqNum, normas e o que a literatura já fez.
- Pontos: gocbRef, heartbeat, descarte de (st,sq) ≤ último; IEC 62351-6, 62443-3-3, IEEE 802.1X; PowerDuck, Auto-SGCR, GOOSEIDRS, Moore, Herath, Hussain, Girdhar, Oliveira 2023.
- Reaproveitar: `main.tex` §2; `referencias.bib`.
- Números: nenhum. Atenção: descrições dos relacionados foram feitas só por título/resumo (`\todo` ler e comparar).

## 3 Metodologia e arquitetura
- Diz: testbed GNS3 gerado do SCD, atacante, IDS, campanhas e variante 802.1X.
- Pontos: 4 switches + switch central, 5 IEDs, Oráculo, IDS, atacante; `--8021x` (7 nós Docker no autenticador); atacante parte de `molde.pcap` (SEL-351); campanha anterior (script não versionado) × reproduzida (offline, semente 61850, ±10%); latência não comparável entre campanhas.
- Reaproveitar: fig `fig:arquitetura`; texto de `main.tex` §3.
- Números: N=100 por cenário e modo; 600 execuções (4º Marco); GNS3 2.2.61; offset do timer descontado 1,956 µs, Python 3.12.11 (`benchmark/resultados/execucao.json`).

## 4 Modelo de ameaças e casos de uso
- Diz: atacante no mesmo domínio L2, níveis (a)–(d) de capacidade, e os 3 casos de uso.
- Pontos: CU1 masquerade/replay (C1 MAC clonado, C2 MAC próprio); CU2 suppression (salto de stNum); CU3 flooding; fora do modelo: IED/chave-mestra/CA comprometidos.
- Reaproveitar: fig `fig:arvore`; `main.tex` §4.
- Números: flooding 50–2000 pps; suppression Δst ∈ {60…5000}.

## 5 Técnicas e modificações
- Diz: IDS de estado, HMAC simulado, limiar de flooding, 802.1X com vínculo CN↔MAC.
- Pontos: 4 regras do IDS (limiares Δst>50, 20 pps/2 s); HMAC-SHA256 32 B, trailer 0xA0 via Reserved1; 1 hostapd por porta, nftables bridge policy drop, CRL concatenada ao ca_cert, MAC fixo `02:00:<IP hex>`.
- Reaproveitar: figs `fig:estados`, `fig:arq8021x`; tab `tab:camadas`; listas de `main.tex` §5.
- Números: limiar 20 pps; tag 32 B; reautenticação 600 s; CRL recarga 60 s.

## 6 Resultados
- Diz: IDS delimitado; HMAC e custo; limiar; 802.1X no GNS3 (E0–E5) e netns.
- Pontos: ver números abaixo; E4 (cert. válido + MAC próprio) autentica e só o IDS sinaliza por MAC; E5(iii) descartado pelo nft antes do IDS.
- Reaproveitar: tabs `tab:anterior`, `tab:reproduzida`, `tab:hmac`, `tab:limiar`, `tab:8021x`, `tab:normas`; figs `tpr_por_cenario.pdf`, `latencia_por_cenario.pdf`, `sensibilidade_limiar.pdf`; CSVs em `benchmark/resultados/` (`campanha_resumo.csv`, `latencia_hmac_micro.csv`, `sensibilidade_*.csv`).
- Números (fonte):
  - IDS, 4º Marco: 400/500 detecções, C1 0/100, base 0/100 FPR; latência 4,03–5,84 µs (`tab:anterior`; dado bruto não preservado).
  - Reproduzida: sem HMAC idem (400/500); C1 HMAC sem chave 100/100; chave vazada 0/100 (`campanha_resumo.csv`).
  - Custo HMAC: `verify` mediana 11,5 µs (P99 35,3), `sign` 11,0 µs (P99 26,3), 20 000 chamadas (`latencia_hmac_micro.csv`); total por quadro ~17–38 µs, limite 4000 µs.
  - Limiar 20 pps: ataques de 5–18 pps não detectados; limiar 20 dá FPR 0% até 15 pps e 100% a 30 pps (`sensibilidade_*.csv`, `tab:limiar`).
  - GNS3 (GNS3.md): base 5 `auth_aceita`, 0 para o atacante, `ping` 3/3, 0,519 ms; E0 `ping` 3/3, 0,468 ms; E1/E2/E3 `ping` 0/3; E2 serial 100B; E3 `mac_divergente`; E4 `MASQUERADE`; E4b 5 pkts/1760 B; E5 (i) `auth_fail`, (ii) `masquerade`, (iii) 5 pkts/1930 B sem alerta novo.
  - netns: 11 execuções, 8×30/0, 2×29/0, 1×28/2; imagens: 16/0 (`autenticador-8021x/evidencias/`).

## 7 Discussão, limitações e trabalhos futuros
- Diz: o que cada camada resolve/não resolve e o que não foi provado.
- Pontos: C1 estrutural para IDS passivo; HMAC não cobre replay/flooding, depende de chaves; 802.1X não vê a mensagem; E3 "AUTORIZADA" no supplicant mas recusa no plano de dados; lições (correlação de cert↔porta, race do supplicant = hipótese).
- Reaproveitar: tab `tab:camadas`; `main.tex` §7 (limitações i–xv).
- Números: 34 B (352→386) é inferência (trailer HMAC); netns 1/6 do bug (README do autenticador, não nos logs).
- Futuro: medir latência/overhead EAP-TLS, repetir no GNS3, MACsec, RADIUS, 62351-6 conforme, baseline do SCD.

## 8 Conclusão
- Diz: três camadas complementares; nenhuma suficiente sozinha.
- Pontos: IDS 0% no C1; HMAC 100% sem chave; 802.1X barra quem não tem credencial/cert válido; E4 é o limite.
- Reaproveitar: `main.tex` Conclusão. Números: os mesmos da seção 6.

## Referências
- `artigo/referencias.bib` (`\verif`: edição/ano das normas, páginas SBSeg 2025, venues do GOOSEIDRS e PowerDuck); sem RFC 5216, hostapd, nftables ainda.

## O que NÃO afirmar
- Que o HMAC é conforme à IEC 62351-6 (é simulação; trailer 0xA0 arbitrário, sem gestão de chaves).
- Que HMAC e limiar foram validados no GNS3 (só offline, tráfego sintético, N=100, rajadas legítimas assumidas).
- Taxas ou IC para o GNS3: cada cenário rodou 1 vez; netns não são amostras independentes.
- Latência/overhead de autenticação 802.1X (nunca medidos); latência HMAC é Python em máquina compartilhada, não hardware de IED, e não comparável com a do 4º Marco.
- Que a recusa do E3 vem do TLS (vem do vínculo CN↔MAC); que 34 B é medição (é inferência); que o log `quadro_descartado` conta todos os descartes (degraus de 5; usar o contador do nft).
- E2b, queda de link e CA falsa no GNS3 (só netns); E0 prova porta aberta só pelo `ping`.
- Cláusulas de norma marcadas `\verif`; conteúdo dos trabalhos relacionados (não lidos); CPU da campanha; autores/afiliação.
- Que o 802.1X impede forjar GOOSE (E4: cert. válido + MAC próprio passa); que o IDS "previne" (só detecta).
