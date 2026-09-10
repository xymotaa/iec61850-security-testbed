# ids — detector de anomalias GOOSE (flooding, replay, masquerade, suppression)
# Ver docs/metodologia.md para o racional de usar um detector Python/Scapy
# próprio em vez do Suricata (suporte a protocolos não-IP como o GOOSE não
# está disponível de forma confiável na versão estável do Suricata).

FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        tcpdump iproute2 iputils-ping \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir scapy

WORKDIR /opt/ids
COPY ids_core.py ids.py goose_frame.py entrypoint.sh ./
RUN chmod +x entrypoint.sh

CMD ["./entrypoint.sh"]
