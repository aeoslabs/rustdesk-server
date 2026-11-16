# VideoVault changes to rustdesk-server

Branch `vv/ws-register`, based on the 1.1.16 release. Licence unchanged (AGPL-3.0).

## Peer registration over TCP and WebSocket (hbbs)

Stock hbbs registers peers only over UDP 21116 and answers a registration sent
over TCP or WebSocket with `NOT_SUPPORT`. A peer that can reach the server only
through a WebSocket proxy, such as a Cloudflare tunnel, therefore never comes
online. This change lets it register on that connection:

- `RegisterPk` over TCP/WebSocket runs the same checks as over UDP
  (`check_register_pk`, shared by both).
- On success hbbs keeps the connection (`ws_peers`) and sends everything meant
  for that peer (punch hole, relay and local address requests) down it instead of
  UDP. Every message from the peer marks it online, as `RegisterPeer` does over UDP.
- hbbs sends an empty heartbeat after 20 s of silence; the RustDesk client
  answers it. The connection closes after 90 s without any message. Other
  TCP/WebSocket connections keep the original 30 s idle limit.
- WebSocket connections behind a proxy all arrive as `<real ip>:0`; each now gets
  its own port number so two peers or clients from one address do not collide.

UDP registration is unchanged.

## Build

The image `videovault/rustdesk-hbbs:vv-ws-register-<short sha>` is built from
`docker-vv/Dockerfile.build` by the `vv-ops images` workflow in aeoslabs/video-vault:

```sh
docker build -f docker-vv/Dockerfile.build -t videovault/rustdesk-hbbs:vv-ws-register-<short sha> .
```

`docker-vv/Dockerfile` packs a binary built beforehand (`cargo build --release --bin hbbs`).
