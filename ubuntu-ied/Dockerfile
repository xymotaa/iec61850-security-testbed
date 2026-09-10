# ubuntu-ied — representa um IED simulado (ubuntu-ied-1 a ubuntu-ied-5)
#
# Roda SSH porque é assim que o Oráculo se conecta pra verificar a
# política de senha (modelo cliente-servidor, como descrito no artigo
# original). A política de senha é deixada no padrão do Ubuntu de
# propósito — é exatamente essa configuração "fraca" que o relatório do
# Oráculo vai apontar como não conforme (igual à Fig. 3 do artigo).

FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-server iproute2 iputils-ping net-tools nano \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/run/sshd

# Conta que o Oráculo vai auditar. Senha fraca de propósito (ponto de
# partida "não conforme" — dá pra depois criar uma segunda versão do
# container com política reforçada, pra comparar "antes/depois" no artigo).
RUN useradd -m -s /bin/bash usuario_IED && \
    echo "usuario_IED:senha123" | chpasswd && \
    echo "PermitRootLogin no" >> /etc/ssh/sshd_config && \
    echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config

EXPOSE 22

# O console do GNS3 se conecta diretamente ao processo principal (PID 1) do
# container — por isso o PID 1 precisa ser um shell interativo, não o sshd
# (foi isso que causou o console "mudo" na primeira tentativa). Este script
# sobe o sshd em segundo plano (pro Oráculo conseguir conectar) e entrega o
# terminal pra um bash interativo (pro console do GNS3 funcionar normal).
RUN printf '#!/bin/bash\n/usr/sbin/sshd\nexec /bin/bash\n' > /entrypoint.sh && \
    chmod +x /entrypoint.sh

CMD ["/entrypoint.sh"]