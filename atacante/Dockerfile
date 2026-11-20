FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        tcpdump iproute2 net-tools iputils-ping \
        wpasupplicant openssl \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir scapy

WORKDIR /opt/goose-attack
COPY goose_frame.py goose_auth.py goose_attack.py entrypoint.sh ./
COPY samples/molde.pcap ./molde.pcap
RUN chmod +x entrypoint.sh

# Cliente 802.1X opcional (AUTH_8021X=1); fonte: autenticador-8021x/supplicant/.
COPY supplicant_8021x.sh /usr/local/bin/8021x-supplicant
RUN chmod +x /usr/local/bin/8021x-supplicant

CMD ["./entrypoint.sh"]
