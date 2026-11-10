FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY meshtastic_protobuf_to_json.py .

CMD ["python3", "-u", "/app/meshtastic_protobuf_to_json.py"]
