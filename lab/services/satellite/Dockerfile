FROM python:3.11-slim

WORKDIR /sat


COPY satellite_sim.py cds.py pus_tm.py .
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

ENTRYPOINT ["/sat/entrypoint.sh"]
