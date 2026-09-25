FROM python:3.11-slim

WORKDIR /sat

RUN pip install --no-cache-dir requests

COPY satellite_sim.py .
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

ENTRYPOINT ["/sat/entrypoint.sh"]
