#!/bin/bash
# Uma única instância do ids na topologia -> IP fixo.
ip addr add 192.168.10.30/24 dev eth0 2>/dev/null
ip link set eth0 up 2>/dev/null

exec /bin/bash
