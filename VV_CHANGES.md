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

## Staff lock (hbbs, hq#595)

Without this, any RustDesk client that knows our server and public key can ask to
connect to a peer (the editor still has to accept). With it, only staff can start a
connection; peers registering and accepting are not checked at all.

- A staff client sends a token in the `token` field of `PunchHoleRequest` and
  `RequestRelay`. Stock RustDesk fills that field from the local option
  `access_token` (`RustDesk_local.toml`, `[options]`); vv-term from `--token` or
  `VV_TERM_TOKEN`.
- Token: `vvst1.<exp_unix>.<who>.<hex hmac_sha256(key = S, msg = "vvst1.<exp_unix>.<who>")>`,
  where S is the staff secret used as ASCII bytes, `who` matches `[a-z0-9@._-]{1,64}`,
  and the token is valid while `now < exp <= now + 12 h`. Code and unit tests:
  `src/staff_token.rs` (`cargo test --lib staff_token`).
- Settings (environment): `VV_STAFF_MODE` = `off` (default, as before), `log` (check
  and log, let everything through) or `enforce` (refuse without a valid token; any
  value other than off/log also means enforce). `VV_STAFF_SECRET` = S, from a host-only
  env file. hbbs logs the mode at start, and whether a secret is set, never the secret.
- Checked: every `PunchHoleRequest` (TCP and WebSocket; hbbs ignores it over UDP) and
  every `RequestRelay` sent to hbbs. These are the only two messages that make hbbs
  contact a peer for a new connection (PunchHole, FetchLocalAddr, RequestRelay).
- Refused the way an offline peer is: a punch request gets `PunchHoleResponse` with
  failure `OFFLINE`; a relay request gets no answer, as for an unknown peer.
- hbbs blanks the token before it forwards a `RequestRelay` to the peer, so an editor's
  machine never sees a staff token.
- Every check logs one line with the requester address, target peer id, the token's
  `who` (the claimed `who` when the token is invalid), the reason, the mode and the
  outcome: `staff-lock: punch from <addr> to peer <id> who=<who> check=ok mode=enforce -> allowed`
  (or `check=failed (<reason>)`). The wording avoids `token=` and `secret=`, which
  ssh-nas and the logs gateway mask.

hbbr is unchanged. It pairs two connections by uuid, and a peer only connects to hbbr
with a uuid it got through hbbs (from a `PunchHole` it answers with its own new uuid,
or from a forwarded `RequestRelay`). Both go through the check above, and a uuid is a
random v4 known only to the two sides, removed from hbbr's table once paired, so a
client that goes straight to hbbr has nobody to pair with.

Not covered: a stolen valid token works for anyone until it expires (at most 12 h);
a peer with RustDesk's direct IP access turned on can be reached without hbbs (off in
the editors' build).
