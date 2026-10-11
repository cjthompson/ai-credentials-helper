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

## Startup and passphrase

At startup, `--serve` calls the existing passphrase helper once, before binding the socket. It prompts in an interactive terminal. A noninteractive launch must provide `CLAUDE_CREDENTIALS_PASSPHRASE`; if no passphrase is available, the command exits without listening. The passphrase remains in memory for the daemon's lifetime. It is never logged or accepted from a command-line argument.

`--request` obtains the same passphrase once before connecting. The daemon verifies each request with it before reading any credential store.

## Request and response flow

Each TCP connection carries one encrypted request naming one agent. The daemon authenticates and validates the request, selects that backend, reads its credential document, wraps it in the existing agent-labeled transfer envelope, encrypts it with the existing transfer crypto, sends the response, and closes the connection. The daemon does not write its credential stores.

`--agent all` makes two sequential requests, one for Claude and one for Codex. Each response uses the existing single-agent transfer envelope. The requester verifies the response's agent label, validates the credential document with the matching backend, and imports it into that local store. It reports the outcome for each agent and exits nonzero if either request or import fails. A failure can leave one store updated and the other unchanged; the two backend stores do not support a shared atomic write.

The request has a distinct, versioned message type so an older helper cannot mistake a request for a credential transfer. A wrong passphrase, malformed request, or unsupported message is rejected before credentials are read. Response frames remain encrypted and authenticated, and invalid responses are rejected before the requester writes a store.

## Listener behavior

The daemon accepts repeated requests until interrupted. Requests are processed sequentially, one connection at a time. An invalid or timed-out request closes that connection and does not stop the listener. Request and response reads use bounded sizes and timeouts. Ctrl-C closes the listening socket and exits cleanly.

The listener binds to all IPv4 interfaces by default so another host can connect. Operators can pass a specific LAN or VPN address with `--bind`. The passphrase is the request authorization secret; anyone who knows it can request either backend, including both.

## Compatibility and error handling

- Existing `--send` and `--receive` flags and wire behavior remain unchanged.
- Existing commands retain their current Claude default.
- `--agent all` is rejected outside `--request`.
- Binding failures and missing noninteractive passphrases fail before the daemon starts accepting requests.
- Diagnostics may include the peer address, selected agent, and outcome, but never credential contents or the passphrase.

## Acceptance scenarios

- The parser accepts valid `--serve` and `--request` combinations and rejects incompatible modes.
- A requester can fetch Claude or Codex credentials from a daemon using isolated test stores.
- `--agent all` requests both stores, imports each response into its matching store, and reports each outcome.
- A wrong passphrase or malformed request causes no server-side store read or write and does not terminate the daemon.
- After a rejected request, the same daemon can serve a valid request.
- Existing one-shot send/receive behavior remains unchanged.
