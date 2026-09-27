FROM rust:1.85-bookworm AS indexer-build
WORKDIR /src
COPY indexer/Cargo.toml indexer/Cargo.lock ./
COPY indexer/src ./src
RUN cargo build --release --locked

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PCAP_DIR=/pcaps
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tshark \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY --from=indexer-build /src/target/release/packettrain-index /usr/local/bin/packettrain-index
COPY app.py index.html ./
COPY packettrain ./packettrain
RUN useradd --uid 10001 --create-home packettrain && mkdir /cache && chown packettrain:packettrain /cache
USER packettrain
EXPOSE 8080
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "2", "--threads", "2", "--timeout", "240", "app:app"]
