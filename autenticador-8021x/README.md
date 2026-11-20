# autenticador-8021x — switch L2 com IEEE 802.1X (EAP-TLS) real

Implementa, no testbed, a recomendação dos slides da disciplina
(*"mandatória a adoção de IEEE 802.1X + IEC 62351-6"*): um nó que atua como
**switch autenticador** — nenhum dispositivo troca tráfego de dados antes de
provar sua identidade com um **certificado X.509** (EAP-TLS, autenticação
mútua), e o certificado é **vinculado ao endereço MAC** do dispositivo.

Não é simulação: `hostapd` (v2.10, driver `wired`, servidor EAP embutido) fala
EAPOL de verdade com o `wpa_supplicant` dos clientes; o encaminhamento é
controlado por `nftables` (família `bridge`).

**Fora do escopo (trabalho futuro):** MACsec (IEEE 802.1AE — cifra/integridade
do quadro), servidor RADIUS externo (aqui o servidor EAP é o embutido no
hostapd), VLAN dinâmica por usuário e PKI de produção.

## Arquitetura

```
 ied-1 ─┐                       ┌──────────────── autenticador-8021x ────────────────┐
 ied-2 ─┤                       │  eth0..eth8  ──(portas da ponte br0)               │
 oraculo┤  EAPOL (01:80:C2:00:00:03)           │                                    │
 ids ───┼──────────────────────►│  hostapd (1 processo e 1 config POR PORTA)          │
 publ. ─┤  EAP-TLS              │      │ log de depuração                            │
 atac. ─┘                       │      ▼                                              │
                                │  autenticador.py ── inventario.json (CN -> MAC)     │
                                │      │ add/delete element                           │
                                │      ▼                                              │
                                │  nftables bridge: set autorizados {porta . MAC}     │
                                │  política: drop  ─►  eventos.jsonl                  │
                                └─────────────────────────────────────────────────────┘
```

1. O supplicant do nó envia EAPOL-Start; o hostapd conduz o EAP-TLS (certificado
   de servidor assinado pela CA de teste; certificado de cliente exigido).
2. Ao fim, o `autenticador.py` (que lê o log do hostapd) conhece o **subject do
   certificado validado** e o MAC de origem, e decide: CN no inventário **e** MAC
   daquele CN → adiciona `(porta, MAC)` ao set `autorizados`; senão, rejeita e
   derruba a sessão (`hostapd_cli deauthenticate`).
3. As regras do nftables (`regras.nft`) só encaminham um quadro se o par
   *(porta de entrada, MAC de origem)* estiver autorizado **e** a porta de
   saída tiver ao menos um dispositivo autorizado. O resto é descartado e o
   par fica registrado no set dinâmico `descartados` (evidência).

### Decisões e por quê

| Decisão | Motivo (evidência) |
|---|---|
| **Um processo hostapd e um arquivo de configuração por porta**, gerados do mesmo template | O driver `wired` rejeita vários `bss=` no mesmo arquivo (`Failed to add BSS`, testado). Processo separado por porta também é o que torna a correlação certificado↔porta inequívoca: as linhas de TLS (`peer certificate`) não trazem a interface, então com um único processo dois MACs iguais em portas diferentes (MAC clonado) podiam ter o certificado atribuído à porta errada (observado em 1 de 6 execuções do `teste_netns.sh`, corrigido). |
| **Ler o log do hostapd em vez de `hostapd_cli -a`** | O ctrl_iface só expõe `dot1xAuthSessionUserName` = identidade EAP **declarada** pelo cliente (testado: um cliente pode declarar qualquer nome). O subject **validado pelo TLS** só aparece no log (`authsrv: peer certificate: depth=0 ... subject=...`). Ler evento e certificado do mesmo fluxo também elimina condição de corrida. Consequência: depende do formato de log do hostapd 2.10 (fixado pela imagem; trechos reais cobertos por teste). |
| **CRL dentro do `ca_cert`** (`ca.pem` + `crl.pem` concatenados) + `check_crl=1` + `crl_reload_interval` | Verificado no binário da build Debian (hostapd 2.10): existem `check_crl`, `crl_reload_interval` e `check_cert_subject`, mas **não existe diretiva `crl=`**; com OpenSSL a CRL é lida do mesmo arquivo da CA. Testado: cert revogado → `error 23 (certificate revoked)`; atualizar o arquivo em operação é aplicado após `crl_reload_interval`. |
| **nftables na família `bridge`, hook `forward`, política `drop`** | Funciona com `iifname . ether saddr` e `oifname`; não exige `br_netfilter` nem iptables. Sets com estado vivo, sem recarregar regras. |
| **EAPOL não passa pelas regras** | `01:80:C2:00:00:03` é endereço link-local: a ponte Linux não o encaminha e o hostapd o recebe direto na porta (testado). |
| **O IDS também autentica (certificado `ids-1`)** | É a solução preferida para o IDS enxergar GOOSE: uma vez autorizado, sua porta recebe o multicast inundado pela ponte, como qualquer outra. Para equipamento sem supplicant existe `PORTAS_CONFIAVEIS` (ver abaixo). |

### Vínculo identidade ↔ endereço (diferencial)

`inventario.json` mapeia **CN do certificado → MACs permitidos** (gerado do SCD,
ver abaixo). Um certificado válido apresentado por um MAC que não é o do seu
dono é rejeitado com `mac_divergente`. Além disso, o par é *(porta, MAC)*:
depois de autenticado, um quadro com MAC de origem diferente do autenticado
(spoofing) é descartado por regra (`quadro_descartado`).

## Eventos (`/var/log/8021x/eventos.jsonl`)

Uma linha JSON por evento: `ts` (UTC), `evento`, `iface`, `mac`, `cn`, `serial`,
`motivo`, `detalhe`.

| `evento` | Quando |
|---|---|
| `auth_aceita` | EAP-TLS ok **e** vínculo CN↔MAC ok: par liberado |
| `auth_rejeitada` | `motivo`: `sem_certificado` (cliente recusa EAP-TLS por não ter credencial), `certificado_invalido` (CA desconhecida, expirado etc.; `detalhe` traz o erro do OpenSSL), `certificado_revogado`, `cn_fora_do_inventario`, `mac_divergente`, `falha_eap` |
| `sessao_encerrada` | logoff/desconexão, falha na reautenticação ou queda de link (`motivo: link_down`) |
| `quadro_descartado` | par (porta, MAC) tentou enviar sem estar autorizado; `pacotes` = contador acumulado |
| `autenticador_iniciado` / `autenticador_encerrado` | ciclo do supervisor |

Um dispositivo **sem supplicant** (ex.: atacante que só clona MAC) não gera
`auth_rejeitada` — ele nunca fala EAPOL —, aparece apenas em `quadro_descartado`.

## Variáveis de ambiente (autenticador)

| Variável | Padrão | Efeito |
|---|---|---|
| `AUTENTICADOR_MODO` | `8021x` | `aberto` = switch L2 comum, sem 802.1X (referência do cenário E0) |
| `AUTENTICADOR_PORTAS` | `9` | usa `eth0..ethN-1` que existirem (o GNS3 cria um `ethN` por adaptador) |
| `AUTENTICADOR_IFACES` | — | lista explícita de interfaces (usada nos testes com veth) |
| `PORTAS_CONFIAVEIS` | — | ex.: `"eth7"`: porta **sem 802.1X**, tráfego livre. Só para equipamento que não tem supplicant; é uma exceção de segurança (qualquer coisa nessa porta é aceita) |
| `REAUTH_PERIODO` | `600` | segundos entre reautenticações (janela de exposição se o nó for trocado sem derrubar o link) |
| `CRL_RELOAD` | `60` | segundos entre releituras da CRL pelo hostapd |
| `AUTENTICADOR_SEM_CRL=1` | — | desliga a checagem de CRL (não recomendado) |
| `AUTENTICADOR_DEBUG=1` | — | grava o log bruto do hostapd em `/var/log/8021x/hostapd.log` |

Volumes (persistentes no GNS3): `/etc/8021x` (`ca.pem`, `cert.pem`, `key.pem`,
`crl.pem`, `inventario.json`) e `/var/log/8021x`.

Operação em execução (console do `autenticador-8021x`):

```bash
autenticador-ctl estado            # pares autorizados + últimos eventos
autenticador-ctl recarregar-crl    # após copiar uma nova crl.pem para /etc/8021x
autenticador-ctl reautenticar      # força nova autenticação de todos (revogados caem na hora)
```

## Supplicant nos nós (`AUTH_8021X=1`)

As imagens `ubuntu-ied`, `oraculo`, `ids` e `atacante` trazem `wpa_supplicant`
(`-Dwired`, `eap=TLS`, `eapol_flags=0`, `ca_cert`/`client_cert`/`private_key`,
`domain_suffix_match` para validar o servidor) e o comando `8021x-supplicant`.
**Desligado por padrão**: sem `AUTH_8021X=1` o comportamento das imagens é o de
antes. Com `AUTH_8021X=1` o `entrypoint.sh` configura o IP como sempre e inicia
o supplicant em background; a rede só passa após a autorização (o supplicant
reinicia sozinho se a porta ficar 20 s sem autorizar ou se o link voltar).

```bash
8021x-supplicant start|stop|status
AUTH_8021X_CERT_DIR=/etc/8021x/alternativos/revogado-1 8021x-supplicant start   # outro certificado
```

Variáveis: `AUTH_8021X_CERT_DIR` (`/etc/8021x`), `AUTH_8021X_IFACE` (`eth0`),
`AUTH_8021X_TIMEOUT` (`60`), `AUTH_8021X_RETRY` (`20`), `AUTH_8021X_SERVER_NAME`
(`autenticador-8021x`). A fonte única é `supplicant/supplicant_8021x.sh`; cada
imagem recebe uma cópia (`tests/test_supplicant_copias.py` falha se divergirem).
A imagem `atacante` aceita também `ATACANTE_IP` (padrão `192.168.10.40`) — é
assim que ela vira o `publicador-1` (`192.168.10.50`).

## Passo a passo (GNS3)

```bash
# 1) imagens (a partir da raiz do repositório)
for d in ubuntu-ied oraculo atacante ids autenticador-8021x; do
  (cd $d && docker build -t $d:latest .)
done
# registre `autenticador-8021x` como template Docker no GNS3, como as demais
# (atacante/README.md), com 9 adaptadores.

# 2) PKI de teste, inventário e topologia
pki/gerar_pki.sh
cd extracao-scd
python3 gerar_topologia_gns3.py dados.json --out subestacao_8021x.gns3 --8021x   # grava também inventario.json
mkdir -p ~/GNS3/projects/subestacao_8021x && cp subestacao_8021x.gns3 ~/GNS3/projects/subestacao_8021x/
cd ../pki
python3 instalar_no_gns3.py ~/GNS3/projects/subestacao_8021x --inventario ../extracao-scd/inventario.json

# 3) abra o projeto no GNS3, Ctrl+A e Start. Roteiro: changelog/guia-testes-5marco.md
```

A topologia `subestacao_8021x` **não usa Switch1..4**: os switches nativos do
GNS3 podem inundar EAPOL e não têm Spanning Tree. O autenticador é o único
elemento L2 e cada dispositivo vai ligado direto a uma porta dele (adaptador
`ethN`). A topologia original (`subestacao.gns3`) não é alterada.

MACs: o GNS3 gera MACs aleatórios por nó; para o vínculo CN↔MAC ser
determinístico o gerador fixa o MAC de cada nó (`custom_adapters`) com o
esquema `02:00:<IP em hexa>` (o `publicador-1` usa o MAC de origem do GOOSE do
`molde.pcap`, `00:30:a7:01:b3:16`, para o IDS ver o mesmo emissor do baseline).
O inventário vem do mesmo código (`extracao-scd/inventario_8021x.py`):

```bash
python3 extracao-scd/inventario_8021x.py extracao-scd/dados.json --out inventario.json
```

Atenção: o número de IEDs da topologia é o do JSON de entrada (o `dados.json` de
exemplo tem 2); `pki/gerar_pki.sh` emite 5 certificados `ubuntu-ied-N` (`--ieds N`).

## Validação executada

Tudo em Docker `--privileged` (clientes em *network namespaces*, par veth direto
na ponte do container — sem passar pela ponte do host, que descartaria o EAPOL):

* `./teste_netns.sh` — hostapd + wpa_supplicant + nftables reais, 9 clientes.
  Prova: cliente com certificado válido autentica e troca tráfego; sem
  credencial, certificado revogado, CA falsa, CN fora do inventário e MAC
  clonado em outra porta **não** passam; MAC forjado depois de autenticar é
  descartado; queda/volta do link revoga e o cliente reautentica sozinho;
  revogação em operação (`recarregar-crl` + `reautenticar`) derruba o cliente.
  Log e eventos em `evidencias/`.
* `./teste_imagens_clientes.sh` — o supplicant **embutido em cada uma das 4
  imagens reais** autentica contra o autenticador.
* Testes unitários (Python `unittest`, sem dependências):
  `cd tests && python3 -m unittest discover -p 'test_*.py'`; mais
  `extracao-scd/tests`, `pki/tests`.

* **GNS3 real** (20/11/2026, GNS3 2.2.61): cenários E0 a E5 executados no
  projeto `subestacao_8021x`, 1 execução por cenário. Resultados e evidências em
  `evidencias/gns3/RESULTADOS_GNS3.md`.

**Não validado no GNS3:** revogação em operação (E2b, só em `netns`), overhead
ou latência de autenticação e repetições estatísticas.

## Limitações e riscos conhecidos

* **802.1X autentica o dispositivo, não a mensagem.** Um nó com certificado
  válido e MAC próprio autentica e publica GOOSE forjado (cenário E4). Mitiga-se
  com `ids --auth` (HMAC estilo 62351-6) e com o IDS; por isso a defesa em
  profundidade (E5).
* **Sem MACsec**: os quadros não são cifrados nem têm integridade; um nó na
  mesma porta/segmento físico ainda pode escutar. É o trabalho futuro natural.
* **Janela de reautenticação**: se o dispositivo for trocado sem que o link
  caia ou o supplicant faça logoff, o par fica autorizado até a próxima
  reautenticação (`REAUTH_PERIODO`). No GNS3 remover/recriar o link nem sempre
  derruba o *carrier* do `ethN`.
* **Acoplamento ao log do hostapd 2.10**: outra versão pode mudar o texto das
  linhas usadas (`peer certificate`, `BE_AUTH entering state RESPONSE`, ...).
  A imagem fixa a versão (Debian bookworm) e os testes cobrem os formatos.
* **Vários dispositivos na mesma porta** funcionam (par por MAC), mas a
  correlação certificado↔estação é feita por processo (portas nunca se misturam) e,
  dentro de uma porta, por uma fila FIFO por MAC. Se o hostapd de uma porta
  morrer, o supervisor revoga os pares dela (fail-closed).
* **Queda do supervisor**: se o `autenticador.py` morrer de forma abrupta (kill -9),
  as regras do nftables permanecem: quem já estava autorizado continua passando
  (nada novo é autorizado, e sem log não há revogação) até o container reiniciar.
  Se só o hostapd de uma porta morrer, o supervisor revoga os pares dela.
* **Fail-closed**: sem inventário/certificados o `iniciar_autenticador.sh`
  recusa subir e informa o motivo. Em `AUTENTICADOR_MODO=aberto` não há proteção.
* PKI e chaves são de laboratório (ver `pki/README.md`). Revogação só vale após
  recarregar a CRL.
