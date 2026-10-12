# Persistent Credential Request Daemon

**Date:** 2026-10-11

**Status:** For review

## Goal

Let a second host request credentials from a running `ai-credentials-helper` process. The requester selects Claude credentials, Codex credentials, or both. The serving host reads and sends the selected credentials without changing its own stores.

The existing one-shot `--send` and `--receive` modes keep their current behavior.

## Command-line interface

Start a daemon:

```text
credentials-helper --serve [--bind 0.0.0.0] [--port 47299]
```

Request credentials:

```text
credentials-helper --request <host> --agent claude|codex|all [--send-port 47299]
```

`--agent` is required with `--request`; `all` is valid only for that mode. `--serve` accepts requests for either backend and does not select an agent at startup. The default serving address is `0.0.0.0`; `--bind` can restrict it to a specific reachable interface. The listener uses the existing `--port` option and requests use the existing `--send-port` option.

`--serve` rejects `--agent` and `--force`; `--bind` is valid only with `--serve`. `--request` supports `--force` for local Codex imports using the existing expiry bypass, while retaining shape validation. Neither new mode accepts `--oauth-only` or another primary mode. Request hosts must be nonempty and must not begin with `-`; ports for the new modes must be between 1 and 65535.

## Startup and passphrase

At startup, `--serve` calls the existing passphrase helper once, before binding the socket. It prompts in an interactive terminal. A noninteractive launch must provide `CLAUDE_CREDENTIALS_PASSPHRASE`; if no passphrase is available, the command exits without listening. The passphrase remains in memory for the daemon's lifetime. It is never logged or accepted from a command-line argument.

`--request` obtains the same passphrase once before connecting. The daemon verifies each request with it before reading any credential store.

## Request and response flow

Each TCP connection carries one encrypted request naming one agent and a fresh request nonce. The daemon authenticates and validates the request, selects that backend, reads its credential document, wraps it in the existing agent-labeled transfer envelope, places that envelope in a response bound to the request nonce, encrypts it with the existing transfer crypto, sends the response, and closes the connection. The daemon does not write its credential stores.

`--agent all` makes two sequential requests, one for Claude and one for Codex, with a separate fresh nonce for each. It attempts the second agent even if the first request or import fails. Each successful response contains the existing single-agent transfer envelope. The requester verifies the response's type, version, nonce, and agent label, validates the credential document with the matching backend, and imports it into that local store. It reports the outcome for each agent and exits nonzero if either request or import fails. A failure can leave one store updated and the other unchanged; the two backend stores do not support a shared atomic write.

Requests and responses have distinct, versioned message types so an older helper cannot mistake a request or response for a credential transfer. A wrong passphrase, malformed request, or unsupported message is rejected before credentials are read. Response frames remain encrypted and authenticated, and invalid responses are rejected before the requester writes a store.

## Request protocol and freshness

The new protocol uses the existing encrypted two-line frame, with a JSON document as its plaintext. It does not change the existing one-shot transfer envelope or ACK format. Required fields are:

- Request: `type: "credential-request"`, `version: 1`, `agent: "claude" | "codex"`, and `nonce`.
- Successful response: `type: "credential-response"`, `version: 1`, `agent`, `nonce`, `status: "ok"`, and `envelope` containing the existing agent-labeled transfer envelope as a string.
- Failed response: the same response type, version, agent, and nonce, with `status: "error"` and a fixed `error` code instead of an envelope.

The requester generates the nonce from 32 cryptographically random bytes, encoded as 64 lowercase hexadecimal characters, for every connection attempt, including retries. The daemon validates its shape and echoes it inside the authenticated response. The requester requires an exact match to its outstanding nonce and agent, and also requires the inner envelope's agent to match. Missing fields, duplicate JSON keys, invalid field types, unsupported versions or statuses, and inconsistent success/error fields are rejected. Requests must name a supported individual backend; `all` is a client-side operation.

A captured response for an earlier request must fail nonce verification before any local store write, even if its authentication tag and credentials are otherwise valid. A replayed request can cause another server-side read, but its response remains bound to the old nonce; this protocol does not promise server-side request replay suppression. The nonce establishes response freshness, not individual host identity: authorization still depends on possession of the shared passphrase.

## Transport and framing

On Linux and WSL, the requester uses native sockets. On macOS, it preserves the existing outbound transport through Apple's `nc`, which avoids the Local Network Privacy restriction documented in the current sender. Both transports send the complete encrypted request and half-close their write side, while keeping the read side open. The daemon reads the request to EOF, sends one encrypted response, and closes the connection; the requester reads the response to EOF before verifying it. A partial frame or missing response is a failure.

The new response reader accumulates multiple chunks rather than reusing the existing sender's single `recv(65535)` ACK read. Request frames are limited to 16 KiB; response frames use the existing `MAX_PAYLOAD` limit, including encryption and protocol overhead. Limits apply to bytes received before decryption. The macOS transport must enforce the same bounds while reading `nc` output, rather than buffering unlimited subprocess output and checking its size afterward. On timeout or oversize output, it terminates and reaps the subprocess and closes its pipes. Changes to support this exchange must preserve existing `--send` transport and ACK behavior.

## Listener behavior

The daemon accepts repeated requests until interrupted. Requests are processed sequentially, one connection at a time. An invalid or timed-out request closes that connection and does not stop the listener.

Each accepted connection has an absolute 30-second deadline, measured with a monotonic clock from acceptance through request reading, backend processing, and response writing. Socket operations use the remaining time; receiving another chunk does not reset the deadline. Backend subprocess calls retain their existing timeouts, capped by the remaining connection budget. The daemon checks the deadline before reading a store and before sending a response. Response writes are bounded too, so a client that stops reading cannot indefinitely block the listener.

The requester retains the existing 10-second connection timeout and has an absolute 30-second exchange deadline after connecting, covering request writing and response reading. The macOS subprocess transport caps its entire runtime at 30 seconds, including connection establishment, because `nc` does not expose a reliable connection timestamp; an idle timeout in `nc` alone is insufficient. Each agent in `all` gets its own bounded attempt. Local import begins only after the complete response has been verified.

Ctrl-C closes the active connection and listening socket and exits cleanly. The requester also cleans up any active `nc` subprocess when interrupted.

The listener binds to all IPv4 interfaces by default so another host can connect. Operators can pass a specific LAN or VPN address with `--bind`. The passphrase is the request authorization secret; anyone who knows it can request either backend, including both.

## Compatibility and error handling

- Existing `--send` and `--receive` flags and wire behavior remain unchanged.
- Existing commands retain their current Claude default.
- `--agent all` is rejected outside `--request`.
- Binding failures and missing noninteractive passphrases fail before the daemon starts accepting requests.
- Missing or unreadable stores, Keychain subprocess failures or timeouts, and client disconnects fail only the current connection. Expected backend and transport exceptions are caught inside the per-connection loop so the listener continues accepting requests.
- Once a request has been authenticated and validated, backend failures receive an encrypted, nonce-bound error response when the connection and deadline permit. Use fixed codes such as `credentials-unavailable` and `backend-failure`; do not send raw backend exception text. Unauthenticated or malformed requests are closed without a response. A timeout, disconnect, missing response, or unverifiable response is a requester failure and causes no local import.
- Diagnostics may include the peer address, selected agent, and outcome, but never credential contents or the passphrase.
- New daemon/request diagnostics must not reuse the existing verbose receive path that prints an access token. Backend errors must be sanitized before logging or display.

## Acceptance scenarios

- The parser accepts valid `--serve` and `--request` combinations and rejects incompatible modes.
- A requester can fetch Claude or Codex credentials from a daemon using isolated test stores.
- `--agent all` requests both stores, imports each response into its matching store, and reports each outcome.
- When the first agent's request or import fails, `all` still attempts the second agent and exits nonzero, preserving any successful import.
- A wrong passphrase or malformed request causes no server-side store read or write and does not terminate the daemon.
- A captured valid response with an earlier nonce, a mismatched outer or inner agent label, or an unsupported message type/version is rejected before any local store write.
- Protocol parsing rejects missing fields, duplicate JSON keys, invalid nonces, and inconsistent success/error fields. Existing one-shot receivers reject the new request and response plaintexts without writing a store.
- After a rejected request, the same daemon can serve a valid request.
- A peer that trickles request bytes or stops reading a response is disconnected within the absolute deadline, and the daemon then serves a valid request.
- Missing credentials, unreadable stores, Keychain failures/timeouts, and disconnects leave server stores unchanged and do not terminate the daemon. Authenticated backend error responses are verified and reported without a local import.
- Fragmented responses, including responses larger than a single receive buffer but within the configured limit, are assembled completely on native and macOS transports. Truncated and oversized frames fail without a local import.
- macOS requests use Apple `nc`, preserve half-close and reply behavior, enforce byte and runtime limits, and clean up the subprocess on failure or interruption. Linux/WSL requests use native sockets.
- Ctrl-C while idle or handling a connection closes sockets cleanly; requester interruption cleans up its transport subprocess.
- Verbose daemon and requester diagnostics contain neither synthetic credential tokens nor the passphrase, including on backend failures.
- Existing one-shot send/receive behavior remains unchanged.
