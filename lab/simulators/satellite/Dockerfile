# SpaceVE-1 Satellite Container
# Builds NASA cFS (Core Flight System) from source on Ubuntu 22.04
# cFS is the actual NASA flight software used on real spacecraft
#
# Build context: lab/simulators/satellite/
#
# What runs inside this container:
#   core-cpu1        The cFS executive — manages all flight apps
#   ci_lab_app       Command Ingest Lab — accepts CCSDS commands over UDP 1234
#   to_lab_app       Telemetry Output Lab — sends telemetry over UDP
#   sch_lab_app      Scheduler — drives periodic housekeeping at 1 Hz
#   hk_app           Housekeeping — aggregates telemetry from all apps
#   sample_app       Example mission app (camera payload stub)
#
# Attack surface:
#   UDP 1234 — ci_lab_app listens here, no authentication
#   Any valid CCSDS packet with correct checksum will be executed

FROM ubuntu:22.04

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    python3 \
    python3-pip \
    libelf-dev \
    libexpat1-dev \
    curl \
    net-tools \
    iproute2 \
    iputils-ping \
    procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /cfs

RUN git clone --recurse-submodules --depth 1 \
    https://github.com/nasa/cFS.git /cfs

COPY cfs_mission_defs/ /cfs/spaceve1_defs/

RUN cp -r /cfs/sample_defs/* /cfs/spaceve1_defs/ 2>/dev/null || true

ENV MISSION_DEFS=/cfs/spaceve1_defs
ENV CFS_APP_PATH=/cfs/apps

RUN cmake \
    -DCMAKE_BUILD_TYPE=debug \
    -DCMAKE_INSTALL_PREFIX=/cfs/build/exe \
    -DMISSION_DEFS=/cfs/spaceve1_defs \
    -Bbuild/pc-linux \
    -DENABLE_UNIT_TESTS=false \
    . 2>&1 || \
    (cd /cfs && cmake \
    -DCMAKE_BUILD_TYPE=debug \
    -DCMAKE_INSTALL_PREFIX=/cfs/build/exe \
    -Bbuild/pc-linux \
    . 2>&1)

RUN cmake --build /cfs/build/pc-linux -- -j$(nproc) 2>&1 || true
RUN cmake --install /cfs/build/pc-linux 2>&1 || true

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

RUN mkdir -p /cfs/build/exe/cpu1/log

EXPOSE 1234/udp

ENTRYPOINT ["/entrypoint.sh"]
