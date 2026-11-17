FROM python:3.11-slim
RUN pip install --no-cache-dir psycopg2-binary
COPY receive_sync.py /app/receive_sync.py
COPY receive_payloads.py /app/receive_payloads.py
ENTRYPOINT ["python3", "/app/receive_sync.py"]
