# Mission Operations Center (MOC) Container
# Based on PWNCUBE architecture (ElectronicCats/PWNCUBE, GPL-3.0)
#
# What runs inside:
#   Flask web app     — MOC dashboard and command interface on port 8080
#   UDP listener      — Receives telemetry from satellite on port 1235
#   Command forwarder — Forwards commands to satellite with no source verification
#
# Intentional misconfigurations (training targets):
#   - Default credentials: admin / admin123
#   - No source IP validation on command submission
#   - Telemetry stored in plaintext SQLite
#   - Web session tokens are weak and predictable
#   - No rate limiting on command interface

FROM ubuntu:22.04

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    curl \
    net-tools \
    iproute2 \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

COPY server.py .
COPY tlm_receiver.py .
COPY templates/ ./templates/
COPY static/ ./static/

RUN mkdir -p /app/data

EXPOSE 8080
EXPOSE 1235/udp

CMD ["python3", "server.py"]
