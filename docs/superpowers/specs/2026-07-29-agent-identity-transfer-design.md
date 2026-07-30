# Design: Agent identity on the transfer wire

## Summary

`--send` currently transmits a credential blob with no indication of *which agent's* credentials it is. The receiver writes whatever arrives into whatever store its own `--agent` flag selected (default `claude`). This document specifies a small, authenticated envelope inside the encrypted payload that names the sending agent, receiver-side auto-detection of that name, and a mutual mismatch failure when the receiver has pinned a different agent.

Target behaviour:

| Sender | Receiver | Result |
|---|---|---|
| `--send --agent codex` | `--receive` (no `--agent`) | Receiver adopts `codex`, writes `~/.codex/auth.json`. Both exit 0. |
| `--send --agent codex` | `--receive --agent codex` | Same, agent pinned and confirmed. Both exit 0. |
| `--send --agent codex` | `--receive --agent claude` | **Both** print an agent-mismatch error and exit 1. Receiver's store untouched. |
| `--send` (no `--agent`, i.e. claude) | `--receive --agent codex` | Mismatch, as above. |

## Motivation (a real, reproducible failure today)

The claude backend writes whatever it is given, verbatim, with no shape check. I verified this against the actual code:

```
$ .venv/bin/python -c "from ai_credentials_helper.backends import claude; \
    print(claude.parse_blob('{\"tokens\":{\"access_token\":\"a.b.c\"}}'))"
{'tokens': {'access_token': 'a.b.c'}}
```

`claude.parse_blob` (`ai_credentials_helper/backends/claude.py:43`) is `json.loads` on a `{`-prefixed string — a Codex `auth.json` passes it, and `_do_receive` then calls `creds.write(content)`, which for claude is an unconditional `security add-generic-password -U`. So `--send --agent codex` into a bare `--receive` today **overwrites the Claude Code keychain entry with Codex credentials**, and the user's only symptom is that Claude Code stops authenticating.

The reverse direction is already protected: `codex.validate_blob` rejects a claude blob at write time (verified — `codex.write('{"claudeAiOauth":{...}}')` raises `CredentialsError: missing or non-dict 'tokens' object`). So the hole is one-directional today, but shape-sniffing is the wrong fix in general: it is a guess about intent. An explicit, authenticated label is the right fix, and it also lets the receiver be run without `--agent` at all — which is the ergonomic win the task asks for.

## Verified assumptions

Everything below was checked in this worktree at the baseline commit (`79f4cae`), not assumed.

1. **The baseline test suite is green.** `.venv/bin/pytest -q` → `128 passed`. Any breakage attributed to this change is genuinely caused by it.

2. **`/usr/bin/nc` supports a receiver→sender reply after the sender's stdin EOF.** This is load-bearing: the "both ends report the mismatch" requirement needs a back-channel, and `_do_send` delegates the outbound write to `nc` (see `cli.py:48-53` — a Homebrew/uv venv python is blocked from LAN `connect()` by macOS Local Network Privacy; `nc` is an Apple platform binary and is exempt). I ran a listener that read to EOF, then wrote a line back:

   ```
   server got: b'hello-payload'
   ERR agent-mismatch          # printed by nc on stdout
   nc rc=0 elapsed=0s
   ```

   So: `nc` half-closes its write side on stdin EOF (the server sees EOF and can complete its read loop unchanged), keeps the read side open, prints the reply on **stdout**, and exits promptly with rc 0 once the server closes. `subprocess.run(..., capture_output=True)` in `_do_send` already captures that stdout and currently discards it. Two consequences the implementer must internalise: the reply is available at zero protocol cost, and **`nc`'s exit code does not reflect the reply** — the sender's exit status must come from parsing stdout.

3. **`--send`/`--receive` in `credentials-helper.sh` are *not* interoperable with the Python CLI and never were.** `grep -n 'openssl\|pbkdf2\|encrypt' credentials-helper.sh` returns nothing; the bash `--send` pipes raw keychain bytes to a socket (lines 218-249) while the Python `--send` transmits an AES-CBC+HMAC frame. Therefore **changing the plaintext that goes inside the encrypted frame breaks no other implementation in this repo**, and the bash script needs no change for this feature. (The `transfer_crypto` module docstring claiming the wire format is "shared with the standalone `claude-credentials.sh`" is stale with respect to transfer framing; only the KDF/AES *primitive* choice is shared, and the openssl interop tests in `tests/test_transfer_crypto.py:143-176` exercise only that primitive. Those tests are unaffected by this change — worth correcting the docstring while in the file.)

4. **PBKDF2 cost is affordable for an extra derivation per side.** `hashlib.pbkdf2_hmac('sha256', ..., 600000, dklen=80)` measures **225 ms** on this machine. The authenticated-ACK design below adds one derivation on each end (~0.22 s), against a `nc -w 10` idle timeout and a `SEND_TIMEOUT + 5 = 15 s` subprocess timeout. Comfortable margin.

5. **Only two test files touch the CLI.** `grep -n 'cli\.\|main(' tests/test_claude_backend.py tests/test_codex_backend.py` → no output. Signature changes to `_do_receive`/`_do_send` are contained to `tests/test_cli_agent.py` and `tests/test_cli_live_transfer.py`.

6. **`argparse` cannot distinguish `--agent claude` from the default today.** `--agent` is declared with `default="claude"` (`cli.py:120-125`), so `args.agent` is `"claude"` in both cases. Receiver auto-detection *requires* telling those apart, so the default must move out of the parser. This is the one unavoidable behavioural ripple; see "Explicitness" below.

7. **Credential payloads may legitimately contain newlines.** `codex.read_raw()` returns `AUTH_PATH.read_text()` verbatim minus one trailing newline — a pretty-printed `auth.json` is multi-line. The envelope must therefore be "first line is the header, everything after the first `\n` is payload, verbatim", not a line-oriented format.

## Design

### 1. Where the agent name goes: inside the ciphertext

The agent label is added to the **plaintext that is encrypted**, not as a cleartext prefix on the frame. Rationale, in threat terms:

- Inside the ciphertext, the label is confidential (an observer cannot tell whether Claude or Codex credentials are moving, modulo the length side-channel that already exists) and integrity-protected by the existing encrypt-then-MAC construction — flipping it requires forging an HMAC-SHA256 tag under a PBKDF2-600k-derived key.
- Outside, an on-path attacker could rewrite `agent=codex` → `agent=claude` and steer a bare `--receive` into writing a Codex blob into the Claude keychain — i.e. re-create, remotely and deliberately, the exact corruption bug this feature exists to prevent. That is disqualifying.

There is no cost to putting it inside: the receiver already decrypts before doing anything with the payload (`cli.py:295-302`).

### 2. Envelope format

New module `ai_credentials_helper/transfer_envelope.py` (text formats only — no sockets, no crypto, so it is unit-testable in isolation).

```
ai-credentials-helper/1 agent=<name>\n<payload bytes, verbatim>
```

- `MAGIC = "ai-credentials-helper/1"`. The `1` is the envelope major version.
- Header is the text up to the first `\n`; payload is everything after it, byte-for-byte (assumption 7).
- Header tokens after the magic are whitespace-separated `key=value`. `agent` is required. **Unknown keys are ignored** so a future version can add fields (e.g. `oauth-only=true`) without a major bump; an unknown *major version* is rejected.
- `agent` must match `^[a-z0-9][a-z0-9_-]{0,31}$` and must resolve via `backends.get_backend()`. Validate the shape *before* interpolating it into any message — it is peer-supplied text that ends up on a terminal.
- `wrap(agent, payload) -> str`, `unwrap(text) -> (agent, payload)`, `EnvelopeError`.

Why a magic header line rather than a JSON envelope with the blob as a string field: a JSON envelope would be ambiguous with a legacy bare claude blob (both start with `{`), would force base64/escaping of the payload, and would break the "write exactly the bytes we were given" property that `claude.write` depends on. The magic prefix cannot collide with either payload form Claude Code stores (`{`-JSON or lowercase hex).

### 3. Unlabelled (legacy) payloads are rejected

A decrypted payload that does not start with `MAGIC` is rejected with a specific message ("payload has no agent label; the sender is running an older version — upgrade both ends"), the store is left untouched, and exit is 1.

This is the security-conservative choice and I recommend it: the alternative (fall back to the receiver's `--agent`-or-default) silently preserves exactly the corruption path described in Motivation, for an indefinite window. The cost is that both machines must be upgraded together — acceptable for a personally-installed tool at version 1.0.0 with a `git clone` + `install.py` distribution. If the maintainer disagrees, the escape hatch is an explicit opt-in flag (`--allow-unlabeled`), but I am deliberately leaving that out of scope rather than shipping a permissive default.

### 4. Receiver: detect, or compare and fail

`_do_receive` gains the requested agent and the force flag as parameters, because the effective backend is no longer known before the payload is decrypted:

```
_do_receive(port, *, verbose, requested_agent: str | None, force: bool) -> int
```

Sequence:

1. Passphrase, bind, accept, read to EOF, decrypt — all unchanged.
2. `unwrap()` the plaintext → `wire_agent`, `payload`.
3. If `requested_agent is not None and requested_agent != wire_agent`: print `Error: agent mismatch — sender sent 'codex', this receiver is pinned to 'claude'; <store> left unchanged`, send an `agent-mismatch` ACK (see §6), return 1. **No store is touched.**
4. Otherwise `creds.set_backend(wire_agent)` and print `Detected agent: <wire_agent> (from sender)` on stderr **before** writing, so a user running a bare `--receive` sees which store is about to change.
5. Apply `--force` *here* (after `set_backend`, which resets `FORCE_WRITE`), not in `main()`, and emit the existing `WARNING: --force` line at this point.
6. `parse_blob` / `write` / success message / verbose token dump — unchanged.
7. Send the `ok` ACK after the write succeeds.

Error messages emitted *before* step 2 (empty connection, decryption failure) cannot name a store meaningfully when the receiver was not pinned. `_store_label()` should get a neutral fallback ("the credential store") when no agent has been resolved yet; when the receiver *was* pinned, keep naming the pinned store. Existing tests assert `f"{cli._store_label()} left unchanged"` with the backend explicitly set, so they keep working if the pinned path preserves today's wording.

### 5. Sender

`_do_send` wraps before encrypting:

```python
plaintext = transfer_envelope.wrap(creds.backend_name(), payload)
frame = transfer_crypto.encrypt(plaintext, passphrase).encode()
```

`creds.backend_name()` is the right source (it reflects the `set_backend` call `main()` already made) rather than re-reading `args.agent`.

After `nc` returns, parse `proc.stdout` (assumption 2):

- Empty → keep today's `Sent N encrypted bytes...` message and return 0, with a trailing note that no acknowledgement was received (older receiver, or the receiver died). Preserves back-compat with an un-upgraded receiver.
- A verifiable ACK with `status=ok` → today's message, return 0.
- A verifiable ACK with `status=agent-mismatch` → print the mismatch error (naming both agents) and **return 1**.
- A verifiable ACK with `status=rejected` → print the receiver's reason and return 1.
- A line that fails MAC verification → print a warning that an unverifiable response was received (do not print its contents), and fall back to the "no acknowledgement" path.

Note the behavioural side-benefit: today a sender reports success even when the receiver rejected the payload outright. This makes the sender's exit code reflect the receiver's outcome. Call it out in the changelog; it is test-visible.

### 6. The acknowledgement line is authenticated

Format, one line, ASCII:

```
ai-credentials-helper/1 status=<ok|agent-mismatch|rejected> detail=<text> <hex-tag>
```

`hex-tag = HMAC-SHA256(mac_key, b"ack\x00" + salt + b"\x00" + <the line text preceding the tag>)`, where `mac_key` and `salt` are the third derived key and the salt **of the frame that was just sent** — i.e. both sides can compute it, and nobody else can.

New helpers in `transfer_crypto.py` (key derivation stays in the crypto module):

- `frame_salt(frame: str) -> bytes` — reuse the existing line-1 parsing/validation from `decrypt`; factor the shared parsing out rather than duplicating it.
- `mac_key_for_frame(frame: str, passphrase: str) -> bytes` — `_derive(passphrase, frame_salt(frame))[2]`.

Both sides call it once (measured 225 ms, assumption 4). `detail` is constrained to `[A-Za-z0-9 _.:=-]{0,120}` and validated on receipt before printing.

Why authenticate a status line at all — the honest accounting is in the threat model below. Short version: it costs one function, ~0.2 s, and it removes the ability of an on-path attacker to fabricate "delivered successfully" or to manufacture spurious mismatch errors. Replay is prevented for free because the tag is bound to the per-transfer random salt.

Timing caveat: the `ok` ACK is written after the store write, which on the claude backend shells out to `security` and could in principle block on a Keychain prompt. If that exceeds `nc -w 10`, the sender reports a send-level failure even though the receive succeeded. Mitigation: `agent-mismatch` and decrypt/validate `rejected` ACKs are sent *immediately* when known (fast paths), and the ACK is documented as advisory — the receiver's own exit code and stderr are authoritative for what happened to the store.

### 7. Explicitness of `--agent` (the one ripple)

Change the parser to `default=None` and resolve centrally:

```python
requested_agent = args.agent            # None means "not specified"
creds.set_backend(requested_agent or "claude")
```

- Every non-receive mode behaves exactly as before (`claude` remains the default).
- `--receive` uses `requested_agent is None` to mean "adopt the sender's agent".
- `main()`'s `force_codex_write` computation must stop looking at `args.agent` for the receive path (the agent is not known yet) and pass `force` down to `_do_receive`; `--import` keeps its current behaviour keyed on the resolved agent.
- `main()`'s `finally` block that resets `FORCE_WRITE` on `creds._backend` remains correct — after `_do_receive` switches backends, it resets the *new* one, which is the one that was forced.

**Required test update:** `tests/test_cli_agent.py::test_cli_default_agent_is_claude` asserts `parser.parse_args(["--raw"]).agent == "claude"` and will now see `None`. Rewrite it to assert the resolved value through whatever helper does the resolution, so it still guards the back-compat property it was written for. `test_force_activates_for_codex_receive_and_resets` spies on `_do_receive(_port, verbose=False)` and asserts `FORCE_WRITE` is already `True` at call time; that contract moves inside `_do_receive`, so the test must be reworked to assert the flag is set at *write* time under the resolved backend.

## Threat model: what is on the wire, and what an attacker can do to it

The transport is plain TCP on port 47299 with no endpoint authentication; the only secret is the shared passphrase. Items in italics are unchanged by this design and listed for completeness, because the honest answer to "what does this feature expose" requires the baseline.

**1. Connection metadata (source/destination IP, port, timestamp, byte count).** *Pre-existing.* Visible to any on-path observer. It reveals that a credential transfer occurred between two named hosts and roughly how large the blob was. Payload size weakly correlates with agent type (a Claude keychain blob and a Codex `auth.json` differ in size), and AES-CBC padding only rounds to 16 bytes. **This change adds a fixed ~40-byte header**, which shifts every length by a constant and therefore does not change what the length leaks. An attacker who wants to know which agent is moving can guess from length whether or not we ship this feature; the header does not make that materially worse, and no padding scheme is proposed here (out of scope, and it would be defeated by the blob-size difference anyway).

**2. The encrypted frame (base64 `salt||ciphertext`, plus hex HMAC tag).** *Pre-existing construction, new plaintext contents.*
- *Read:* yields nothing without the passphrase. The **agent name is now inside this envelope**, so it inherits that confidentiality — this is the whole reason it is not a cleartext prefix.
- *Tamper:* any bit flip in salt, ciphertext, or tag fails the constant-time HMAC check before decryption (`transfer_crypto.decrypt`, verified by `test_tampered_ciphertext_rejected` / `test_tampered_tag_rejected`). The receiver errors out and the store is untouched. Specifically, **an attacker cannot relabel the agent** to redirect a Codex blob into the Keychain.
- *Replay:* **no anti-replay exists**, before or after this change. A captured frame can be re-sent later to any receiver running `--receive` with the same passphrase, re-installing stale credentials. The agent label does not change this; a replayed frame replays its original label too, so it cannot be used to cross agents. Explicitly out of scope — fixing it needs a receiver-supplied nonce, i.e. the handshake ruled out below.
- *Drop/block:* denial of service. The receiver sits until `RECV_TIMEOUT` (30 s) and exits 1.
- *Record for offline attack:* the frame is a PBKDF2-600k-protected oracle for offline passphrase guessing. **The passphrase is the entire security boundary** — a weak one is the dominant risk in this system and no code change here helps.

**3. The agent name (new, inside the ciphertext).** Confidential and integrity-protected as above. The residual risk is *not* network-positional: it is that a peer who **does** hold the passphrase can now steer a bare `--receive` into writing a store the receiving user did not name — e.g. label a frame `agent=claude` and have the receiver overwrite the Keychain when the user was thinking about Codex. Assessment: a passphrase holder can already overwrite the receiver's store today (that is what `--receive` is for), so this does not cross a new boundary; it only changes *which* store. Mitigations in the design: the receiver prints `Detected agent: X (from sender)` before writing, the backend's own `parse_blob`/`validate_blob` still gate the write, and a user who cares can pin with `--agent` and get a hard failure instead.

**4. The acknowledgement line (new, receiver → sender, plaintext TCP).**
- *Unauthenticated version (rejected):* an on-path attacker could inject a forged `status=ok` so the sender prints success when the receiver actually rejected the payload, or inject `status=agent-mismatch` to manufacture a false alarm. It could not cause any credential to be written anywhere — the ACK is display-only and the sender must never act on it beyond printing and exit-coding. Still, "the tool told me it landed" is exactly the kind of claim that should not be attacker-controlled.
- *As designed:* the tag is HMAC-SHA256 under the frame's `mac_key`, so forging it requires the passphrase; and it is bound to the frame's fresh random salt, so an ACK captured from an earlier transfer will not verify against a new one. An attacker can still **suppress** the ACK (drop it, or close the connection), which downgrades the sender to "no acknowledgement received" — fail-open on *reporting*, never on *writing*. That is the correct failure direction: the receiver's own exit code remains authoritative.
- `detail` text arriving from the peer is charset-restricted and length-capped before it is printed, so a passphrase-holding peer cannot inject terminal control sequences into the sender's stderr.

**5. Endpoint identity.** *Pre-existing.* `--send <host>` trusts DNS/ARP/the user's typing. A misdirected or hijacked connection delivers the encrypted frame to an unintended host, where it is useless without the passphrase. There is no certificate, no host key, no pinning.

**One property this feature deliberately does not provide:** the mismatch is detected *after* the credentials have crossed the network and been decrypted in the receiver's memory. It is a wrong-store guard, not a confidentiality control. Avoiding the transmission would require the receiver to announce its pinned agent before the sender writes — a handshake the current sender cannot perform, because outbound writes are delegated to `nc` (assumption 2 and the rationale at `cli.py:48-53`: a third-party-venv python is blocked from LAN `connect()` by macOS Local Network Privacy) and `printf | nc` sends immediately. Accepting the post-hoc check is a deliberate trade against re-opening that platform problem.

## Optional companion hardening (recommended, sequence separately)

Give the claude backend a `validate_blob` requiring the parsed document to be a dict containing a dict-valued `claudeAiOauth`, and call it from `claude.write` (or tighten `claude.parse_blob`). This closes the corruption path from Motivation independently of the envelope, giving defence in depth for the case where a passphrase-holding peer mislabels a frame. Two things to check before doing it: `oauth_only_json()` emits `{"claudeAiOauth": null}` when the key is absent, which such a check would start rejecting (arguably correct, but it is a behaviour change), and `tests/test_claude_backend.py` may contain fixtures that write minimal blobs. I am flagging this as a separate step rather than folding it in, because it changes `--import` semantics for the claude backend and deserves its own review.

## Implementation order

1. `ai_credentials_helper/transfer_envelope.py` — `MAGIC`, `EnvelopeError`, `wrap`, `unwrap`, `ack`, `read_ack`. Pure functions, no I/O.
2. `ai_credentials_helper/transfer_crypto.py` — factor line-1 parsing out of `decrypt`; add `frame_salt` and `mac_key_for_frame`. Do not touch the KDF, the wire frame, or `encrypt`/`decrypt` signatures (the openssl interop tests and the KDF known-answer vector must keep passing byte-for-byte). Fix the stale `claude-credentials.sh` docstring claim.
3. `cli.py` — `--agent` `default=None` + central resolution; `_do_send` wraps and interprets the ACK; `_do_receive` gains `requested_agent`/`force`, does unwrap → mismatch check → `set_backend` → detected-agent notice → force → write → ACK; `_store_label()` neutral fallback; move `--force` warning into the receive path.
4. Docs — module docstring in `cli.py`, the `--agent`/`--receive` help strings, the parser epilog, and the README "Encrypted transfer" section (state that the receiver may omit `--agent`, that passing a different one is a hard error on both ends, and that both ends must be upgraded past this version). No `credentials-helper.sh` change (assumption 3), but a one-line note there that its plaintext `--send`/`--receive` do not interoperate with the Python CLI would be honest.
5. Tests.

## Test plan

New, `tests/test_transfer_envelope.py`: wrap/unwrap round-trip including a multi-line payload and a hex-encoded (non-JSON) claude payload; payload preserved byte-for-byte; missing magic rejected; unknown major version rejected; unknown header keys ignored; missing/blank/oversized/illegal-character `agent` rejected; empty payload rejected; ACK round-trip; ACK with a flipped tag rejected; ACK made under a different salt rejected (replay); `detail` charset enforcement.

New/updated in `tests/test_cli_agent.py`: bare `--receive` adopts the wire agent and writes the right store; pinned matching agent succeeds; pinned mismatching agent returns 1, leaves the store unchanged, and emits an ACK with `status=agent-mismatch`; unlabelled legacy payload rejected with the upgrade message; `_do_send` returns 1 on a verified mismatch ACK and 0 with a note on empty stdout; an unverifiable ACK line does not flip the exit code and its contents are not printed; the reworked `--force`-on-receive and default-agent tests from §7.

Updated `tests/test_cli_live_transfer.py`: the existing codex round-trip must still pass unchanged (both ends pass `--agent codex`, so this is a real regression check on the envelope + ACK over a genuine socket). Add a second live case: receiver `--agent claude`, sender `--agent codex`, asserting both processes exit 1, both stderrs mention the mismatch, and `recv_home/.codex/auth.json` and the claude store are untouched. Keep the existing `nc`-availability skip guard.

`tests/test_transfer_crypto.py`: unchanged except for additions covering `frame_salt`/`mac_key_for_frame`. If any existing assertion in that file needs editing, treat it as a signal that the crypto refactor went further than intended.

## Explicitly out of scope

Anti-replay for the credential frame; endpoint/host authentication; a pre-send handshake that would avoid transmitting on a mismatch; length padding to hide agent type; multi-agent or batched transfers; carrying `--oauth-only` on the wire (the header is extensible for it later); any change to `credentials-helper.sh`'s plaintext transfer; and an opt-in flag for accepting unlabelled legacy payloads.

## Open questions for the maintainer

1. Strict rejection of unlabelled payloads (recommended) vs. a fallback to the receiver's `--agent`. This is the only decision here with a real migration cost.
2. Whether the sender should exit non-zero on a `rejected` ACK, or only on `agent-mismatch`. I have specified non-zero for both, on the grounds that "the receiver threw it away" is not success — but it changes exit codes for pre-existing failure modes.
3. Whether to take the claude-side `validate_blob` hardening now or as a follow-up.

### Critical Files for Implementation

- `ai_credentials_helper/cli.py`
- `ai_credentials_helper/transfer_crypto.py`
- `ai_credentials_helper/backends/claude.py`
- `tests/test_cli_agent.py`
- `tests/test_cli_live_transfer.py`
