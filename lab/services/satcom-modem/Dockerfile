FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc wget ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY fw_update_agent.c .
RUN gcc -O2 -o fw_update_agent fw_update_agent.c

EXPOSE 9000
CMD ["/app/fw_update_agent"]
