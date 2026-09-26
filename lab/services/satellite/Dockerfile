FROM python:3.11-slim

WORKDIR /sat


COPY satellite_sim.py cds.py pus_tm.py .
COPY entrypoint.sh .
RUN sed -i 's/\r$//' entrypoint.sh && chmod +x entrypoint.sh

ENTRYPOINT ["/sat/entrypoint.sh"]
