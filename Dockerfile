# syntax=docker/dockerfile:1
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Unprivileged system user with a fixed UID, so volume permissions stay predictable.
RUN useradd --system --uid 10001 --no-create-home gateway

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY gateway.py .

USER 10001

EXPOSE 8080

CMD ["python", "gateway.py"]