# VideoVault build of hbbs: rustdesk-server 1.1.16 plus peer registration over
# TCP/WebSocket (branch vv/ws-register). Build the binary first:
#   cargo build --release --bin hbbs
# then copy target/release/hbbs next to this file and run docker build here.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY hbbs /usr/bin/hbbs
WORKDIR /root
ENV HOME=/root
EXPOSE 21115 21116 21116/udp 21118
