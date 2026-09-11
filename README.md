# iec61850-security-testbed

Extensão do artigo *"Analisador Automático de Segurança Cibernética para
o Setor Elétrico"* (Oliveira & Gurjão, SBSeg 2025 — WTICG), reproduzindo
o ambiente original no GNS3 e ampliando os testes de segurança, conforme
sugerido na própria seção de trabalhos futuros do artigo.

O que o artigo original fazia: extrair a estrutura de comunicação de uma
subestação (via arquivos SCL/SCD, IEC 61850) e montar automaticamente
uma topologia simulada no GNS3, com um container "Oráculo" verificando
conformidade de política de senha (IEC 62443-3-3 SR 1.3/1.7) dos IEDs.

O que este projeto acrescenta: mais 6 critérios de conformidade da IEC
62443-3-3 (SR 1.1, 1.5, 2.1, 3.1, 5.1, 7.1), e testes ativos de ataque
ao protocolo GOOSE (flooding, replay, masquerade/insertion, suppression)
com um container de detecção (IDS) próprio. Ver `docs/metodologia.md`
para o racional completo.

## Estrutura

```
├── docs/metodologia.md   → metodologia completa (leia primeiro)
├── ubuntu-ied/            → imagem Docker dos IEDs simulados
├── oraculo/                → verificador de conformidade (SSH + 8 SRs da IEC 62443-3-3)
├── atacante/                → ferramenta de ataque GOOSE (Scapy, 4 testes)
├── ids/                      → detector de anomalias GOOSE (Python/Scapy próprio)
└── extracao-scd/              → extração de dados do SCL/SCD — pendente
```

## Setup (resumo)

Pré-requisitos: **GNS3 estável (2.2.x)** + **Docker**. Veja
`docs/metodologia.md` se quiser o racional de cada escolha (por que GNS3
em vez de outra ferramenta, por que essa versão, etc).

> ⚠️ Se estiver no Arch/CachyOS: o pacote `gns3-server`/`gns3-gui` do AUR
> aponta hoje pra série 3.x (ainda alpha, instável). Use os pacotes
> `gns3-server-2` / `gns3-gui-2` (série 2.2.x estável) em vez desses.

1. Instale GNS3 + Docker (`pacman`/`apt`, conforme sua distro).
2. Builda as imagens (uma por pasta):
   ```bash
   cd ubuntu-ied && docker build -t ubuntu-ied:latest . && cd ..
   cd oraculo    && docker build -t oraculo:latest .    && cd ..
   cd atacante   && docker build -t atacante:latest .   && cd ..
   cd ids        && docker build -t ids:latest .        && cd ..
   ```
3. Registra cada imagem como template Docker no GNS3 — via API é mais
   confiável que o assistente gráfico (ver exemplo de `curl` em
   `docs/metodologia.md` ou pedir pro histórico do projeto).
4. Monta a topologia: 4 switches em **estrela** a partir de um switch
   central (o switch nativo do GNS3 não tem Spanning Tree — uma malha
   completa entre os switches cria loop de rede) + 5 `ubuntu-ied` +
   `oraculo-1` + `ids-1` + `atacante-1`, todos no mesmo switch central
   (GOOSE é multicast de Camada 2 — precisa estar no mesmo domínio de
   broadcast).
5. Cada container já configura o próprio IP sozinho ao iniciar
   (`entrypoint.sh` em cada pasta) — não precisa configurar nada na mão.

## Status atual

- [x] Topologia base (4 switches + 5 IEDs + oraculo-1 + ids-1 + atacante-1) validada.
- [x] `ubuntu-ied`: SSH + política de senha configurável, IP automático.
- [x] `oraculo`: 8 SRs da IEC 62443-3-3 (1.1, 1.3, 1.5, 1.7, 2.1, 3.1, 5.1, 7.1), validado contra ambiente real.
- [x] `atacante`: núcleo GOOSE validado contra captura real (round-trip byte-a-byte); 4 ataques implementados e testados.
- [x] `ids`: detector próprio (Python/Scapy) — 7 cenários de teste + validação ponta-a-ponta ataque→detecção ao vivo.
- [ ] `extracao-scd/` — não iniciado.
- [ ] Rodar o Oráculo nos 5 IEDs sistematicamente (dataset para a Seção de Resultados).
- [ ] Resultados finais / Resumo Expandido (SBC) — não iniciado.