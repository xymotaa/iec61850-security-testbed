# autenticador-8021x — switch L2 autenticador IEEE 802.1X (EAP-TLS)
#
# Ponte Linux (br0) + hostapd (driver wired, servidor EAP embutido) +
# nftables (família bridge). Ver README.md.

FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        hostapd nftables iproute2 iputils-ping tcpdump \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/autenticador
COPY autenticador_core.py autenticador.py regras.nft hostapd.conf.tmpl eap_user \
     iniciar_autenticador.sh autenticador_ctl.sh entrypoint.sh ./
RUN chmod +x iniciar_autenticador.sh autenticador_ctl.sh entrypoint.sh \
    && ln -s /opt/autenticador/autenticador_ctl.sh /usr/local/bin/autenticador-ctl

# Certificados e inventário vêm por volume (/etc/8021x) e os eventos saem
# em /var/log/8021x: no GNS3, declare ambos como volumes persistentes do nó.
CMD ["./entrypoint.sh"]
