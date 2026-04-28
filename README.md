<img width="512" height="512" alt="SchrodingersPacket" src="https://github.com/user-attachments/assets/4593326c-1f68-40b2-bdf8-1de7bf19f154" />

# Packet Loss Characterization Tool (PLCT)

A combined client/server utility for measuring, logging, and analyzing UDP packet
loss between two endpoints. Designed to produce structured reports suitable for
documenting degraded ISP service — particularly the kind of intermittent packet
loss that kills video calls.

## How it works

The client sends small UDP probe packets to the server at a configurable rate
(default: 10 probes/second). The server echoes each packet back unchanged so the
client can measure round-trip time. Probes that don't return within the timeout
window are recorded as lost.

Results are written to a compact binary log file (`.plct`). The `report` subcommand
reads one or more log files and produces a detailed offline analysis.

## Usage

### Server

Run this on a machine with a stable internet connection (a VPS works well):

```
python3 packetloss.py server [--port 5201]
```

### Client

Run this on the machine whose connection you want to characterize:

```
python3 packetloss.py client <server_host> [options]
```

Options:

| Flag | Default | Description |
|------|---------|-------------|
| `--port` | 5201 | UDP port to connect to |
| `--interval MS` | 100 | Probe send interval in milliseconds |
| `--size BYTES` | 128 | Wire size of each probe packet |
| `--timeout MS` | 2000 | Time before a probe is declared lost |
| `--duration SEC` | — | Stop automatically after N seconds |
| `--log FILE` | `packetloss_TIMESTAMP.plct` | Log file path |

Press `Ctrl-C` to stop. A summary and the log file path are printed on exit.

### Report

Analyze one or more log files (they are merged and sorted chronologically):

```
python3 packetloss.py report <logfile> [logfile ...]
```

The report includes:

- **Overall statistics** — total probes, loss rate, RTT min/mean/median/p95/p99/jitter (p95 = 95th percentile: 95% of packets had an RTT at or below this value; p99 = 99th percentile: the worst 1% threshold)
- **Recent daily trend** — per-day loss with a linear trend direction (INCREASING / DECREASING / HOLDING) and vKill count
- **Burst analysis** — consecutive-loss sequences: count, length distribution, duration, and gap between bursts
- **Loss by hour of day** — bar chart of loss rate for each hour
- **Loss by day of week** — bar chart per weekday
- **Worst 5-minute windows** — top 10 sliding windows ranked by loss percentage
- **Call-killing windows (vKills)** — any 30-second window with ≥ 5% loss that would noticeably degrade a video call
- **RTT by hour of day** — average and p95 RTT per hour
- **Assessment** — plain-English verdict with congestion pattern analysis

### Publishing a report to the web

`stdin2html.py` wraps plain-text output in a styled, dark-mode-aware HTML page:

```
python3 packetloss.py report *.plct | python3 stdin2html.py --title "My ISP report" -o index.html
```

`update_report.sh` is a convenience script that regenerates `index.html` from the
collected log files and copies it to a web server with `scp`.

## Log file format

Binary `.plct` files begin with an 8-byte magic (`PLCTLOG\x01`) followed by
fixed-width 16-byte records:

| Field | Type | Description |
|-------|------|-------------|
| `seq` | uint32 LE | Probe sequence number |
| `epoch` | double LE | Send timestamp (Unix epoch) |
| `rtt_ms` | float32 LE | Round-trip time in ms, or `NaN` for a lost packet |

Legacy JSONL files from earlier versions of the tool are also supported by the
`report` subcommand.

## Requirements

Python 3.6+ with no external dependencies.
