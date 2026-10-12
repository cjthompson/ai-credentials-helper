"""Persistent read-only credential serving and bounded request transports."""

import logging
import os
import selectors
import socket
import subprocess
import sys
import time

from ai_credentials_helper import request_protocol as protocol
from ai_credentials_helper import transfer_crypto
from ai_credentials_helper.backends import claude, get_backend

log = logging.getLogger(__name__)
REQUEST_LIMIT = 16 * 1024
EXCHANGE_TIMEOUT = 30
CONNECT_TIMEOUT = 10


def remaining(deadline: float) -> float:
    budget = deadline - time.monotonic()
    if budget <= 0:
        raise TimeoutError("credential exchange deadline exceeded")
    return budget


def read_frame(conn, limit: int, deadline: float) -> bytes:
    chunks = []
    total = 0
    while True:
        conn.settimeout(remaining(deadline))
        block = conn.recv(min(65536, limit - total + 1))
        if not block:
            return b"".join(chunks)
        total += len(block)
        if total > limit:
            raise protocol.ProtocolError("credential frame exceeds size limit")
        chunks.append(block)


def send_frame(conn, frame: bytes, deadline: float) -> None:
    conn.settimeout(remaining(deadline))
    conn.sendall(frame)


def exchange_native(frame: bytes, host: str, port: int, limit: int) -> bytes:
    with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT) as conn:
        deadline = time.monotonic() + EXCHANGE_TIMEOUT
        send_frame(conn, frame, deadline)
        conn.shutdown(socket.SHUT_WR)
        return read_frame(conn, limit, deadline)


def exchange_nc(frame: bytes, host: str, port: int, limit: int, binary: str) -> bytes:
    # Apple nc uses -G for the connection timeout; -N has unrelated semantics.
    if host.startswith("-"):
        raise protocol.ProtocolError("invalid request host")
    # nc cannot report a stable connection timestamp. Bound its whole lifetime
    # to the exchange budget, including connection establishment.
    deadline = time.monotonic() + EXCHANGE_TIMEOUT
    proc = subprocess.Popen(
        [binary, "-G", str(CONNECT_TIMEOUT), "-w", str(EXCHANGE_TIMEOUT), host, str(port)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        bufsize=0,
    )
    chunks = []
    total = 0
    pending = memoryview(frame)
    try:
        with selectors.DefaultSelector() as selector:
            for pipe, event in ((proc.stdin, selectors.EVENT_WRITE),
                                (proc.stdout, selectors.EVENT_READ)):
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, event)
            while selector.get_map():
                events = selector.select(remaining(deadline))
                for key, _event in events:
                    if key.fileobj is proc.stdin:
                        written = os.write(proc.stdin.fileno(), pending)
                        pending = pending[written:]
                        if not pending:
                            selector.unregister(proc.stdin)
                            proc.stdin.close()  # EOF makes nc half-close the TCP write side.
                    else:
                        block = os.read(proc.stdout.fileno(), min(65536, limit - total + 1))
                        if not block:
                            selector.unregister(proc.stdout)
                            continue
                        total += len(block)
                        if total > limit:
                            raise protocol.ProtocolError("credential frame exceeds size limit")
                        chunks.append(block)
            if proc.wait(timeout=remaining(deadline)) != 0:
                raise OSError("credential request transport failed")
        return b"".join(chunks)
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait()
        proc.stdin.close()
        proc.stdout.close()


def exchange(frame: bytes, host: str, port: int, limit: int, nc_binary: str) -> bytes:
    if sys.platform == "darwin":
        return exchange_nc(frame, host, port, limit, nc_binary)
    if sys.platform == "linux":
        return exchange_native(frame, host, port, limit)
    raise protocol.ProtocolError("credential requests require macOS, Linux, or WSL")


def process_connection(conn, passphrase: str, limit: int, deadline: float) -> None:
    frame = read_frame(conn, REQUEST_LIMIT, deadline)
    text = transfer_crypto.decrypt(frame.decode("utf-8"), passphrase)
    agent, nonce = protocol.read_request(text)
    remaining(deadline)
    backend = get_backend(agent)
    try:
        if backend is claude and claude.KEYCHAIN_SERVICE:
            payload = claude._read_raw_keychain(timeout=min(5, remaining(deadline)))
        else:
            payload = backend.read_raw()
        text = protocol.response(agent, nonce, payload=payload)
    except claude.CredentialsError:
        text = protocol.response(agent, nonce, error="credentials-unavailable")
    except (OSError, ValueError, subprocess.SubprocessError):
        text = protocol.response(agent, nonce, error="backend-failure")
    remaining(deadline)
    response = transfer_crypto.encrypt(text, passphrase).encode()
    if len(response) > limit:
        response = transfer_crypto.encrypt(
            protocol.response(agent, nonce, error="backend-failure"), passphrase
        ).encode()
        if len(response) > limit:
            raise protocol.ProtocolError("credential frame exceeds size limit")
    send_frame(conn, response, deadline)
    log.debug("credential request: agent=%s response sent", agent)


def serve(bind: str, port: int, passphrase: str, limit: int) -> int:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((bind, port))
            listener.listen(16)
            print(f"Serving credential requests on {bind}:{listener.getsockname()[1]}...",
                  file=sys.stderr, flush=True)
            while True:
                conn, peer = listener.accept()
                deadline = time.monotonic() + EXCHANGE_TIMEOUT
                with conn:
                    try:
                        process_connection(conn, passphrase, limit, deadline)
                    except (OSError, ValueError, RecursionError, transfer_crypto.DecryptionError,
                            subprocess.SubprocessError, claude.CredentialsError):
                        # Never log exception text: it can contain credentials or peer bytes.
                        log.debug("credential request: peer=%s connection failed", peer)
    except KeyboardInterrupt:
        return 0


def request_credentials(host: str, port: int, agent: str, passphrase: str,
                        limit: int, nc_binary: str, *, force: bool = False) -> int:
    failed = False
    for selected in protocol.AGENTS if agent == "all" else (agent,):
        backend = get_backend(selected)
        if hasattr(backend, "FORCE_WRITE"):
            backend.FORCE_WRITE = False
        try:
            nonce = protocol.new_nonce()
            frame = transfer_crypto.encrypt(protocol.request(selected, nonce), passphrase).encode()
            reply = exchange(frame, host, port, limit, nc_binary)
            text = transfer_crypto.decrypt(reply.decode("utf-8"), passphrase)
            payload, error = protocol.read_response(text, selected, nonce)
            if error:
                print(f"{selected}: request failed ({error})", file=sys.stderr)
                failed = True
                continue
            if force and selected == "codex":
                backend.FORCE_WRITE = True
                print("WARNING: --force set; skipping backend write-time safety checks",
                      file=sys.stderr)
            backend.validate_blob(backend.parse_blob(payload))
            backend.write(payload)
            print(f"{selected}: credentials imported", file=sys.stderr)
        except (OSError, ValueError, RecursionError, transfer_crypto.DecryptionError,
                subprocess.SubprocessError, claude.CredentialsError):
            print(f"{selected}: request or import failed", file=sys.stderr)
            failed = True
        finally:
            if hasattr(backend, "FORCE_WRITE"):
                backend.FORCE_WRITE = False
    return int(failed)
