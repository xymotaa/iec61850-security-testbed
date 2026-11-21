# Evidência: versão de TLS negociada no EAP-TLS

**Ambiente de depuração — esta medição NÃO foi feita no GNS3.** Ela foi feita em
um contêiner Docker privilegiado (imagem `autenticador-8021x:teste`), com o
`hostapd` e o `wpa_supplicant` no mesmo contêiner, ligados por um par veth (o
cliente em um *network namespace*), e com uma PKI temporária gerada por
`pki/gerar_pki.sh --out`. Data: 21/11/2026 (UTC).

## O que foi medido
A versão de TLS que o EAP-TLS efetivamente negocia com a configuração do
projeto (`hostapd.conf.tmpl` e `supplicant/supplicant_8021x.sh`), que **não fixa**
versão de TLS. O objetivo é saber qual RFC se aplica (RFC 5216 para TLS 1.2;
RFC 9190 para TLS 1.3).

## Resultado
| Modo | Arquivo | Versão negociada |
|---|---|---|
| Configuração do projeto | `saida-configuracao-do-projeto.txt` | **TLS 1.2** (`SSL: Using TLS version TLSv1.2`; suíte `0xc030`, valor IANA de `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`) |
| TLS 1.3 habilitado nas duas pontas (`tls_flags=[ENABLE_TLSv1_3]` no hostapd e `phase1="tls_disable_tlsv1_3=0"` no supplicant) | `saida-tls13-habilitado.txt` | **TLS 1.2** (mesma suíte `0xc030`); o hostapd não registrou erro de configuração |

Nos dois modos o EAP-TLS concluiu com sucesso (`CTRL-EVENT-EAP-SUCCESS`).

Interpretação, não medição direta: no modo com TLS 1.3 habilitado, a primeira
linha `Using TLS version TLSv1.3` do supplicant aparece antes do handshake e é
lida como a versão máxima oferecida; a versão negociada é a que as linhas
seguintes e a suíte `0xc030` indicam, TLS 1.2. **A causa de o TLS 1.3 não ser
negociado nesse modo não foi investigada.**

## Limitações
- O cliente medido é o `wpa_supplicant` 2:2.10-24 do Debian (mesma imagem do
  servidor). No GNS3, o cliente é o da imagem `ubuntu-ied` (`wpa_supplicant` 2.10
  com OpenSSL 3.0.13), que **não foi medido** nessa combinação.
- O servidor (`hostapd` 2:2.10-24, `libssl3t64` 3.5.7) é o mesmo binário e a mesma
  imagem (`autenticador-8021x`) usados no GNS3.
- Nenhum log de evidência do GNS3 registra a versão de TLS negociada.
- Os logs completos de depuração (`-dd`) não são versionados; só as linhas
  filtradas por `medir_versao_tls.sh`.

## Como reproduzir
Ver o cabeçalho de `medir_versao_tls.sh`.
