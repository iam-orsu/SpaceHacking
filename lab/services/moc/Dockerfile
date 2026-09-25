FROM python:3.11-slim
WORKDIR /moc
RUN pip install --no-cache-dir "websockets>=12.0" "aiohttp>=3.9" psycopg2-binary
COPY ccsds_parser.py telemetry_store.py moc_server.py ./
COPY static/ static/
EXPOSE 5000/udp
EXPOSE 8765
EXPOSE 8080
CMD ["python", "moc_server.py"]
