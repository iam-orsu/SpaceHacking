FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir flask psycopg2-binary

COPY gateway.py .
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

EXPOSE 9001

CMD ["/app/entrypoint.sh"]
