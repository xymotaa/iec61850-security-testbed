# oraculo — verificador de conformidade IEC 62443-3-3 (SR 1.3 / SR 1.7)
# Conecta via SSH em cada ubuntu-ied e audita a política de senha.

FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        iproute2 iputils-ping openssh-client \
        wpasupplicant openssl \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir paramiko

WORKDIR /opt/oraculo
COPY oraculo.py entrypoint.sh ./
RUN chmod +x entrypoint.sh

# Cliente 802.1X opcional (AUTH_8021X=1); fonte: autenticador-8021x/supplicant/.
COPY supplicant_8021x.sh /usr/local/bin/8021x-supplicant
RUN chmod +x /usr/local/bin/8021x-supplicant

CMD ["./entrypoint.sh"]
