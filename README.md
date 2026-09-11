# iec61850-security-testbed

Extensão do artigo **"Analisador Automático de Segurança Cibernética
para o Setor Elétrico"** (Oliveira & Gurjão, UFCG — SBSeg 2025, WTICG),
reproduzindo o ambiente original no GNS3 e ampliando os testes de
segurança, conforme sugerido na própria seção de trabalhos futuros do
artigo original.

O artigo original extrai a estrutura de uma subestação (arquivos
SCL/SCD, IEC 61850), monta a topologia no GNS3 e usa um container
"Oráculo" pra checar política de senha dos IEDs (IEC 62443-3-3 SR
1.3/1.7). Este projeto amplia isso com mais 6 critérios de conformidade
(SR 1.1, 1.5, 2.1, 3.1, 5.1, 7.1) e testes ativos de ataque ao
protocolo GOOSE (flooding, replay, masquerade, suppression), com um
detector de anomalias (`ids-1`) próprio.

## Instalação e configuração

Pré-requisitos: **GNS3 estável 2.2.x** + **Docker**.

> ⚠️ Arch/CachyOS: o pacote `gns3-server`/`gns3-gui` do AUR aponta hoje
> pra série 3.x (alpha, instável). Use `gns3-server-2` / `gns3-gui-2`
> (série 2.2.x estável).

1. Instale GNS3 + Docker.
2. Builda as 4 imagens (uma por pasta — `ubuntu-ied`, `oraculo`,
   `atacante`, `ids`):
   ```bash
   cd <pasta> && docker build -t <pasta>:latest . && cd ..
   ```
3. Registre cada imagem como template Docker no GNS3 (via API é mais
   confiável que o assistente gráfico — exemplo em
   `atacante/README.md`).
4. Monte a topologia: 4 switches em **estrela** (o switch nativo do
   GNS3 não roda Spanning Tree — malha completa gera loop) + 5
   `ubuntu-ied` + `oraculo-1` + `ids-1` + `atacante-1`, todos no mesmo
   switch central (GOOSE é multicast de Camada 2).
5. Cada container configura o próprio IP sozinho ao iniciar — não
   precisa configurar nada na mão.

Detalhes, troubleshooting e o racional de cada escolha técnica estão em
`docs/metodologia.md`.

## Testes

| Comando | O que faz |
|---|---|
| `oraculo/oraculo.py <ip>` | Audita um IED (8 SRs da IEC 62443-3-3) via SSH |
| `atacante/goose_attack.py {flood,replay,masquerade,suppress}` | Dispara um dos 4 ataques GOOSE |
| `ids/ids.py --iface eth0 [--log arquivo.jsonl]` | Monitora e alerta sobre os 4 ataques em tempo real |
| `extracao-scd/extrair_scd.py <arquivo.scd>` | Extrai IPs e blocos GOOSE/SV de um SCD real |

Resultados já coletados (5 IEDs auditados, 5 cenários de ataque
testados, 0 falsos positivos) estão em `docs/resultados.md`.

## Estrutura

```
├── docs/           → metodologia.md e resultados.md
├── ubuntu-ied/      → imagem dos IEDs simulados
├── oraculo/          → verificador de conformidade
├── atacante/          → ferramenta de ataque GOOSE
├── ids/                → detector de anomalias GOOSE
└── extracao-scd/        → extração de dados do SCL/SCD
```

## Referências

- Artigo original: Oliveira, L. H. V.; Gurjão, E. C. *Analisador
  Automático de Segurança Cibernética para o Setor Elétrico.* SBSeg
  2025 — WTICG.
  [PDF](https://drive.google.com/file/d/1vWiduvD9pPyCSuB831nNRECYd1Ik2ef5/view?pli=1)