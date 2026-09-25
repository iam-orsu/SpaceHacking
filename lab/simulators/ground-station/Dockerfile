# Ground Station Container
# Simulates the network-accessible command gateway
# between operators and the satellite
#
# Services:
#   TCP 4820 — Command uplink proxy (accepts from any source)
#   TCP 5900 — Status/admin service (default creds: gsoperator/password123)
#
# Intentional misconfigurations:
#   - Accepts commands from any IP in the 192.168.60.0/24 network
#   - No firewall rules between ground-station and MOC segments
#   - Default credentials never changed
#   - No command rate limiting

FROM ubuntu:22.04

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    net-tools \
    iproute2 \
    iputils-ping \
    nmap \
    curl \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install --no-cache-dir flask==3.0.3

WORKDIR /gs

COPY gateway.py .
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

EXPOSE 4820/tcp
EXPOSE 5900/tcp

ENTRYPOINT ["/gs/entrypoint.sh"]
