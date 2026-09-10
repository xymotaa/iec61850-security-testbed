# iec61850-security-testbed

Extensão do artigo *"Analisador Automático de Segurança Cibernética para
o Setor Elétrico"* (Oliveira & Gurjão, SBSeg 2025 — WTICG), reproduzindo
o ambiente original no GNS3 e ampliando os testes de segurança, conforme
sugerido na própria seção de trabalhos futuros do artigo.

O que o artigo original fazia: extrair a estrutura de comunicação de uma
subestação (via arquivos SCL/SCD, IEC 61850) e montar automaticamente
uma topologia simulada no GNS3, com um container "Oráculo" verificando
conformidade de política de senha (IEC 62443-3-3 SR 1.3/1.7) dos IEDs.

O que este projeto acrescenta: mais critérios de conformidade da IEC
62443-3-3, e testes ativos de ataque ao protocolo GOOSE (flooding,
replay, masquerade/insertion, suppression) com um container de detecção
(IDS). Ver `docs/metodologia.md` para o racional completo.

## Estrutura

```
├── docs/metodologia.md   → metodologia completa (leia primeiro)
├── ubuntu-ied/            → imagem Docker dos IEDs simulados
├── oraculo/                → verificador de conformidade (SSH + IEC 62443-3-3)
├── atacante/                → ferramenta de ataque GOOSE (Scapy)
├── ids/                      → detecção (Suricata) — pendente
└── extracao-scd/              → extração de dados do SCL/SCD — pendente
```

## Setup (resumo)

Pré-requisitos: **GNS3 estável (2.2.x)** + **Docker**. Veja
`docs/metodologia.md` se quiser o racional de cada escolha (por que GNS3
em vez de outra ferramenta, por que essa versão, etc).

> ⚠️ Se estiver no Arch/CachyOS: o pacote `gns3-server`/`gns3-gui` do AUR
> aponta hoje pra série 3.x (ainda alpha, instável). Use os pacotes
> `gns3-server-2` / `gns3-gui-2` (série 2.2.x estável) em vez desses.

1. Instale GNS3 + Docker (`pacman`/`apt`, conforme sua distro) e o
   Docker do jeito padrão de cada sistema.
2. Builda as imagens:
   ```bash
   cd ubuntu-ied && docker build -t ubuntu-ied:latest . && cd ..
   cd oraculo    && docker build -t oraculo:latest .    && cd ..
   cd atacante   && docker build -t atacante:latest .   && cd ..
   ```
3. Registra cada imagem como template Docker no GNS3 (**Edit → Preferences
   → Docker → Docker containers → New**, ou via API — ver
   `atacante/README.md` pra um exemplo de chamada via `curl`).
4. Monta a topologia: 4 switches em **estrela** a partir de um switch
   central (o switch nativo do GNS3 não tem Spanning Tree — uma malha
   completa entre os switches cria loop de rede) + 5 `ubuntu-ied` + 1
   `oraculo` conectado ao switch central.

## Status atual

- [x] Topologia base (4 switches + 5 IEDs) validada — conectividade
      completa entre todos os IEDs.
- [x] `ubuntu-ied`: imagem com SSH + política de senha auditável.
- [x] `oraculo`: script de verificação (SR 1.3/1.7) testado.
- [x] `atacante`: núcleo de parsing/crafting GOOSE validado contra
      captura real (round-trip byte-a-byte); 4 ataques implementados.
- [ ] `oraculo-1` integrado na topologia do GNS3.
- [ ] `ids/` (Suricata) — não iniciado.
- [ ] `extracao-scd/` — não iniciado.
- [ ] Resultados finais / Resumo Expandido (SBC) — não iniciado.
