FROM python:3.12-slim

WORKDIR /app

COPY api/requirements.txt /app/api/requirements.txt
RUN pip install --no-cache-dir -r /app/api/requirements.txt

COPY analyzer /app/analyzer
COPY api /app/api
COPY db /app/db
COPY ingest /app/ingest
# The RFC corpus and IANA registries ship with the image: a fresh install builds
# its knowledge base offline, with no call to rfc-editor.org or iana.org.
COPY rfc /app/rfc
COPY iana /app/iana

RUN useradd -m -u 10001 siptrace && mkdir -p /data/uploads && chown -R siptrace /data
USER siptrace

EXPOSE 8000
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
