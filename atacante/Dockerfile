FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        tcpdump iproute2 net-tools iputils-ping \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir scapy

WORKDIR /opt/goose-attack
COPY goose_frame.py goose_attack.py ./

# Ambiente interativo (não usar ENTRYPOINT fixo) — dentro do GNS3 você
# normalmente abre um console no container e roda os comandos manualmente.
CMD ["/bin/bash"]
