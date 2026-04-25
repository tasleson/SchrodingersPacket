#!/usr/bin/env python3
"""
Packet Loss Characterization Tool

A combined client/server program that measures and characterizes UDP packet
loss between two endpoints. Produces detailed reports suitable for filing
complaints with an ISP about degraded service.

Usage:
    Server:  python3 packetloss.py server [--port 5201]
    Client:  python3 packetloss.py client <server_host> [options]
    Report:  python3 packetloss.py report <logfile.jsonl>
"""

import argparse
import collections
import datetime
import json
import math
import os
import select
import signal
import socket
import struct
import sys
import time

# Packet format: 8-byte big-endian sequence number + 8-byte double timestamp
# + optional padding to reach desired packet size
HEADER_FMT = "!Qd"
HEADER_SIZE = struct.calcsize(HEADER_FMT)
MAGIC = b"PLCT"  # Packet Loss Characterization Tool
# Full wire format: 4-byte magic + header + padding
MIN_PACKET = len(MAGIC) + HEADER_SIZE

DEFAULT_PORT = 5201
DEFAULT_INTERVAL_MS = 100  # send a probe every 100 ms
DEFAULT_PACKET_SIZE = 128  # bytes total on the wire
DEFAULT_TIMEOUT_MS = 2000  # consider a packet lost after 2 seconds
STATS_INTERVAL_SEC = 10    # print rolling stats every N seconds


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------

def run_server(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    print(f"[server] listening on UDP port {port}")

    # Track per-client stats so the server log is useful too
    clients = {}  # addr -> {last_seq, received, gaps}

    while True:
        try:
            data, addr = sock.recvfrom(65535)
        except KeyboardInterrupt:
            break

        if len(data) < MIN_PACKET or data[:4] != MAGIC:
            continue

        seq, client_ts = struct.unpack_from(HEADER_FMT, data, 4)

        # Track this client
        if addr not in clients:
            clients[addr] = {"last_seq": seq - 1, "received": 0, "gaps": 0}
            print(f"[server] new client {addr[0]}:{addr[1]}")

        c = clients[addr]
        expected = c["last_seq"] + 1
        if seq > expected:
            missed = seq - expected
            c["gaps"] += missed
        c["last_seq"] = seq
        c["received"] += 1

        # Echo the packet back unchanged — client uses its own timestamp
        # to compute RTT
        sock.sendto(data, addr)

        if c["received"] % 500 == 0:
            total = c["received"] + c["gaps"]
            loss_pct = (c["gaps"] / total * 100) if total else 0
            print(
                f"[server] {addr[0]}:{addr[1]}  "
                f"rx={c['received']}  gaps={c['gaps']}  "
                f"loss={loss_pct:.2f}%"
            )

    sock.close()
    print("\n[server] stopped")
    for addr, c in clients.items():
        total = c["received"] + c["gaps"]
        loss_pct = (c["gaps"] / total * 100) if total else 0
        print(f"  {addr[0]}:{addr[1]}  rx={c['received']}  "
              f"gaps={c['gaps']}  loss={loss_pct:.2f}%")


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

class ProbeTracker:
    """Tracks sent probes and matches them with responses."""

    def __init__(self, timeout_sec):
        self.timeout = timeout_sec
        self.pending = {}        # seq -> send_timestamp
        self.results = []        # list of dicts, one per resolved probe
        self.next_seq = 0
        self.sent = 0
        self.received = 0
        self.lost = 0
        self.rtts = []           # recent RTTs for jitter calc
        self.current_burst = 0   # consecutive losses in progress
        self.bursts = []         # list of burst lengths (completed)

    def record_send(self, seq, ts):
        self.pending[seq] = ts
        self.sent += 1

    def record_recv(self, seq, rtt):
        if seq in self.pending:
            send_ts = self.pending.pop(seq)
            self.received += 1
            self.rtts.append(rtt)
            if self.current_burst > 0:
                self.bursts.append(self.current_burst)
                self.current_burst = 0
            return {
                "seq": seq,
                "send_ts": send_ts,
                "rtt_ms": rtt * 1000,
                "lost": False,
            }
        return None

    def expire_old(self, now):
        """Mark probes that have timed out as lost."""
        expired = []
        for seq, send_ts in list(self.pending.items()):
            if now - send_ts > self.timeout:
                expired.append((seq, send_ts))
                del self.pending[seq]

        for seq, send_ts in expired:
            self.lost += 1
            self.current_burst += 1
            yield {
                "seq": seq,
                "send_ts": send_ts,
                "rtt_ms": None,
                "lost": True,
            }

    def loss_rate(self):
        total = self.received + self.lost
        return (self.lost / total) if total > 0 else 0.0

    def avg_rtt_ms(self):
        if not self.rtts:
            return 0.0
        return sum(self.rtts) / len(self.rtts) * 1000

    def jitter_ms(self):
        """Compute jitter as std-dev of recent RTTs."""
        if len(self.rtts) < 2:
            return 0.0
        mean = sum(self.rtts) / len(self.rtts)
        variance = sum((r - mean) ** 2 for r in self.rtts) / len(self.rtts)
        return math.sqrt(variance) * 1000


def run_client(host, port, interval_ms, packet_size, timeout_ms, duration,
               logfile):
    packet_size = max(packet_size, MIN_PACKET)
    padding = b"\x00" * (packet_size - MIN_PACKET)
    interval = interval_ms / 1000.0
    timeout_sec = timeout_ms / 1000.0

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)

    # Resolve once
    try:
        server_addr = (socket.gethostbyname(host), port)
    except socket.gaierror as e:
        print(f"[client] cannot resolve {host}: {e}", file=sys.stderr)
        sys.exit(1)

    tracker = ProbeTracker(timeout_sec)

    log_fh = None
    if logfile:
        log_fh = open(logfile, "a")
        print(f"[client] logging to {logfile}")

    print(f"[client] target {server_addr[0]}:{server_addr[1]}  "
          f"interval={interval_ms}ms  size={packet_size}B  "
          f"timeout={timeout_ms}ms")
    if duration:
        print(f"[client] will run for {duration} seconds")
    else:
        print("[client] press Ctrl-C to stop")

    start_time = time.time()
    next_send = start_time
    last_stats = start_time
    seq = 0
    running = True

    def handle_sig(signum, frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, handle_sig)
    signal.signal(signal.SIGTERM, handle_sig)

    while running:
        now = time.time()

        if duration and (now - start_time) >= duration:
            break

        # --- Send probes ---
        while next_send <= now:
            send_ts = time.time()
            pkt = MAGIC + struct.pack(HEADER_FMT, seq, send_ts) + padding
            try:
                sock.sendto(pkt, server_addr)
            except OSError as e:
                print(f"[client] send error: {e}", file=sys.stderr)
            tracker.record_send(seq, send_ts)
            seq += 1
            next_send += interval

        # --- Receive responses ---
        while True:
            readable, _, _ = select.select([sock], [], [], 0)
            if not readable:
                break
            try:
                data, _ = sock.recvfrom(65535)
            except OSError:
                break
            if len(data) < MIN_PACKET or data[:4] != MAGIC:
                continue
            resp_seq, send_ts = struct.unpack_from(HEADER_FMT, data, 4)
            rtt = time.time() - send_ts
            result = tracker.record_recv(resp_seq, rtt)
            if result and log_fh:
                log_entry(log_fh, result)

        # --- Expire old probes ---
        now = time.time()
        for result in tracker.expire_old(now):
            if log_fh:
                log_entry(log_fh, result)

        # --- Periodic stats ---
        if now - last_stats >= STATS_INTERVAL_SEC:
            print_rolling_stats(tracker, now - start_time)
            # Keep RTT window manageable
            if len(tracker.rtts) > 1000:
                tracker.rtts = tracker.rtts[-500:]
            last_stats = now

        # Sleep until next event
        sleep_until = min(next_send, now + 0.05)
        sleep_dur = sleep_until - time.time()
        if sleep_dur > 0:
            time.sleep(sleep_dur)

    # Final drain — wait for remaining in-flight probes
    drain_deadline = time.time() + timeout_sec
    while tracker.pending and time.time() < drain_deadline:
        readable, _, _ = select.select([sock], [], [], 0.1)
        if readable:
            try:
                data, _ = sock.recvfrom(65535)
                if len(data) >= MIN_PACKET and data[:4] == MAGIC:
                    resp_seq, send_ts = struct.unpack_from(HEADER_FMT, data, 4)
                    rtt = time.time() - send_ts
                    result = tracker.record_recv(resp_seq, rtt)
                    if result and log_fh:
                        log_entry(log_fh, result)
            except OSError:
                pass
        for result in tracker.expire_old(time.time()):
            if log_fh:
                log_entry(log_fh, result)

    sock.close()

    # Finalize any remaining burst
    if tracker.current_burst > 0:
        tracker.bursts.append(tracker.current_burst)

    print("\n" + "=" * 60)
    print_final_summary(tracker, time.time() - start_time)

    if log_fh:
        log_fh.close()
        print(f"\nDetailed log saved to: {logfile}")
        print(f"Run 'python3 {sys.argv[0]} report {logfile}' for full analysis")


def log_entry(fh, result):
    ts = datetime.datetime.fromtimestamp(result["send_ts"])
    entry = {
        "seq": result["seq"],
        "timestamp": ts.isoformat(),
        "epoch": result["send_ts"],
        "rtt_ms": round(result["rtt_ms"], 3) if result["rtt_ms"] else None,
        "lost": result["lost"],
        "weekday": ts.strftime("%A"),
        "hour": ts.hour,
    }
    fh.write(json.dumps(entry) + "\n")
    fh.flush()


def print_rolling_stats(tracker, elapsed):
    loss = tracker.loss_rate() * 100
    avg_rtt = tracker.avg_rtt_ms()
    jitter = tracker.jitter_ms()
    elapsed_str = str(datetime.timedelta(seconds=int(elapsed)))
    print(
        f"[{elapsed_str}]  sent={tracker.sent}  recv={tracker.received}  "
        f"lost={tracker.lost}  loss={loss:.2f}%  "
        f"rtt={avg_rtt:.1f}ms  jitter={jitter:.1f}ms"
    )


def print_final_summary(tracker, elapsed):
    total = tracker.received + tracker.lost
    loss = tracker.loss_rate() * 100
    avg_rtt = tracker.avg_rtt_ms()
    jitter = tracker.jitter_ms()

    print("PACKET LOSS CHARACTERIZATION — SUMMARY")
    print("=" * 60)
    print(f"Duration:           {datetime.timedelta(seconds=int(elapsed))}")
    print(f"Packets sent:       {tracker.sent}")
    print(f"Packets received:   {tracker.received}")
    print(f"Packets lost:       {tracker.lost}")
    print(f"Loss rate:          {loss:.2f}%")
    print(f"Avg RTT:            {avg_rtt:.2f} ms")
    print(f"Jitter (stddev):    {jitter:.2f} ms")
    if tracker.rtts:
        min_rtt = min(tracker.rtts) * 1000
        max_rtt = max(tracker.rtts) * 1000
        print(f"Min RTT:            {min_rtt:.2f} ms")
        print(f"Max RTT:            {max_rtt:.2f} ms")

    if tracker.bursts:
        print(f"\nLoss bursts:        {len(tracker.bursts)}")
        print(f"  avg length:       {sum(tracker.bursts)/len(tracker.bursts):.1f} packets")
        print(f"  max length:       {max(tracker.bursts)} packets")
        print(f"  min length:       {min(tracker.bursts)} packets")
        # Distribution
        counter = collections.Counter(tracker.bursts)
        print("  distribution:")
        for length in sorted(counter):
            print(f"    {length} packet(s): {counter[length]} occurrence(s)")


# ---------------------------------------------------------------------------
# Report — offline analysis of a log file
# ---------------------------------------------------------------------------

def run_report(logfile):
    if not os.path.exists(logfile):
        print(f"Error: {logfile} not found", file=sys.stderr)
        sys.exit(1)

    entries = []
    with open(logfile) as fh:
        for line in fh:
            line = line.strip()
            if line:
                entries.append(json.loads(line))

    if not entries:
        print("No data in log file.")
        return

    entries.sort(key=lambda e: e["seq"])

    total = len(entries)
    lost_entries = [e for e in entries if e["lost"]]
    recv_entries = [e for e in entries if not e["lost"]]
    loss_pct = len(lost_entries) / total * 100 if total else 0

    first_ts = datetime.datetime.fromisoformat(entries[0]["timestamp"])
    last_ts = datetime.datetime.fromisoformat(entries[-1]["timestamp"])
    duration = last_ts - first_ts

    print("=" * 70)
    print("PACKET LOSS CHARACTERIZATION REPORT")
    print("=" * 70)
    print(f"Log file:       {logfile}")
    print(f"Period:         {first_ts.strftime('%Y-%m-%d %H:%M:%S')} to "
          f"{last_ts.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Duration:       {duration}")
    print(f"Total probes:   {total}")
    print(f"Received:       {len(recv_entries)}")
    print(f"Lost:           {len(lost_entries)}")
    print(f"Overall loss:   {loss_pct:.2f}%")

    if recv_entries:
        rtts = [e["rtt_ms"] for e in recv_entries]
        print(f"\nRTT statistics (ms):")
        print(f"  Min:          {min(rtts):.2f}")
        print(f"  Max:          {max(rtts):.2f}")
        print(f"  Mean:         {sum(rtts)/len(rtts):.2f}")
        sorted_rtts = sorted(rtts)
        p50 = sorted_rtts[len(sorted_rtts) // 2]
        p95 = sorted_rtts[int(len(sorted_rtts) * 0.95)]
        p99 = sorted_rtts[int(len(sorted_rtts) * 0.99)]
        print(f"  Median (p50): {p50:.2f}")
        print(f"  p95:          {p95:.2f}")
        print(f"  p99:          {p99:.2f}")
        mean = sum(rtts) / len(rtts)
        variance = sum((r - mean) ** 2 for r in rtts) / len(rtts)
        print(f"  Jitter (σ):   {math.sqrt(variance):.2f}")

    # --- Burst analysis ---
    print("\n" + "-" * 70)
    print("BURST ANALYSIS")
    print("-" * 70)
    bursts = find_bursts(entries)
    if bursts:
        lengths = [b["length"] for b in bursts]
        durations_ms = [b["duration_ms"] for b in bursts]
        print(f"Total loss bursts:  {len(bursts)}")
        print(f"Burst lengths (consecutive lost packets):")
        print(f"  Min:    {min(lengths)}")
        print(f"  Max:    {max(lengths)}")
        print(f"  Mean:   {sum(lengths)/len(lengths):.1f}")
        print(f"Burst durations:")
        print(f"  Min:    {min(durations_ms):.0f} ms")
        print(f"  Max:    {max(durations_ms):.0f} ms")
        print(f"  Mean:   {sum(durations_ms)/len(durations_ms):.0f} ms")

        counter = collections.Counter(lengths)
        print(f"Burst length distribution:")
        for length in sorted(counter):
            print(f"  {length} packet(s): {counter[length]} time(s)")

        # Gap between bursts
        if len(bursts) > 1:
            gaps = []
            for i in range(1, len(bursts)):
                gap = bursts[i]["start_epoch"] - bursts[i-1]["end_epoch"]
                gaps.append(gap)
            print(f"Time between bursts:")
            print(f"  Min:    {min(gaps):.1f} s")
            print(f"  Max:    {max(gaps):.1f} s")
            print(f"  Mean:   {sum(gaps)/len(gaps):.1f} s")

        # Longest bursts detail
        print(f"\nTop 10 longest bursts:")
        for b in sorted(bursts, key=lambda x: -x["length"])[:10]:
            ts = datetime.datetime.fromtimestamp(b["start_epoch"])
            print(f"  {ts.strftime('%Y-%m-%d %H:%M:%S')} "
                  f"({ts.strftime('%A')})  "
                  f"{b['length']} pkts  {b['duration_ms']:.0f} ms")
    else:
        print("No loss bursts detected.")

    # --- Time-of-day analysis ---
    print("\n" + "-" * 70)
    print("LOSS BY HOUR OF DAY")
    print("-" * 70)
    hour_total = collections.Counter()
    hour_lost = collections.Counter()
    for e in entries:
        h = e["hour"]
        hour_total[h] += 1
        if e["lost"]:
            hour_lost[h] += 1

    print(f"{'Hour':>6}  {'Total':>8}  {'Lost':>8}  {'Loss%':>8}  Bar")
    for h in range(24):
        t = hour_total.get(h, 0)
        l = hour_lost.get(h, 0)
        pct = (l / t * 100) if t > 0 else 0
        bar = "█" * int(pct * 2) if t > 0 else ""
        print(f"{h:>6}  {t:>8}  {l:>8}  {pct:>7.2f}%  {bar}")

    # --- Day-of-week analysis ---
    print("\n" + "-" * 70)
    print("LOSS BY DAY OF WEEK")
    print("-" * 70)
    day_order = ["Monday", "Tuesday", "Wednesday", "Thursday",
                 "Friday", "Saturday", "Sunday"]
    day_total = collections.Counter()
    day_lost = collections.Counter()
    for e in entries:
        d = e["weekday"]
        day_total[d] += 1
        if e["lost"]:
            day_lost[d] += 1

    print(f"{'Day':>12}  {'Total':>8}  {'Lost':>8}  {'Loss%':>8}  Bar")
    for d in day_order:
        t = day_total.get(d, 0)
        l = day_lost.get(d, 0)
        pct = (l / t * 100) if t > 0 else 0
        bar = "█" * int(pct * 2) if t > 0 else ""
        if t > 0:
            print(f"{d:>12}  {t:>8}  {l:>8}  {pct:>7.2f}%  {bar}")

    # --- Time-window analysis (find worst periods) ---
    print("\n" + "-" * 70)
    print("WORST 5-MINUTE WINDOWS (top 10)")
    print("-" * 70)
    windows = find_worst_windows(entries, window_sec=300)
    print(f"{'Start Time':>22}  {'Day':>10}  {'Total':>7}  "
          f"{'Lost':>6}  {'Loss%':>7}")
    for w in windows[:10]:
        ts = datetime.datetime.fromtimestamp(w["start"])
        print(f"{ts.strftime('%Y-%m-%d %H:%M:%S'):>22}  "
              f"{ts.strftime('%A'):>10}  {w['total']:>7}  "
              f"{w['lost']:>6}  {w['loss_pct']:>6.2f}%")

    # --- RTT over time (hourly) ---
    if recv_entries:
        print("\n" + "-" * 70)
        print("AVERAGE RTT BY HOUR OF DAY (ms)")
        print("-" * 70)
        hour_rtts = collections.defaultdict(list)
        for e in recv_entries:
            hour_rtts[e["hour"]].append(e["rtt_ms"])
        print(f"{'Hour':>6}  {'AvgRTT':>8}  {'p95RTT':>8}  {'Count':>8}")
        for h in range(24):
            if h in hour_rtts:
                r = sorted(hour_rtts[h])
                avg = sum(r) / len(r)
                p95 = r[int(len(r) * 0.95)]
                print(f"{h:>6}  {avg:>7.1f}  {p95:>7.1f}  {len(r):>8}")

    # --- Summary assessment ---
    print("\n" + "=" * 70)
    print("ASSESSMENT")
    print("=" * 70)
    if loss_pct < 0.1:
        print("Loss rate is within normal bounds (< 0.1%).")
    elif loss_pct < 1.0:
        print(f"Loss rate of {loss_pct:.2f}% is ELEVATED. This will cause "
              "noticeable degradation for real-time applications (VoIP, "
              "video calls, gaming).")
    elif loss_pct < 5.0:
        print(f"Loss rate of {loss_pct:.2f}% is HIGH. This causes significant "
              "quality issues for all interactive applications and will "
              "reduce TCP throughput.")
    else:
        print(f"Loss rate of {loss_pct:.2f}% is SEVERE. The connection is "
              "substantially degraded. File transfers will be slow, "
              "video calls will be unusable, and interactive applications "
              "will suffer major issues.")

    if bursts:
        avg_burst = sum(lengths) / len(lengths)
        if avg_burst > 5:
            print(f"\nLoss pattern is BURSTY (avg burst = {avg_burst:.1f} "
                  "packets). This suggests congestion or buffer overflow "
                  "rather than random bit errors.")
        elif len(bursts) > 0 and max(lengths) > 10:
            print(f"\nSome large loss bursts detected (max = {max(lengths)} "
                  "packets). This may indicate periodic congestion events "
                  "or route flaps.")

    # Check for time-of-day correlation
    if hour_total:
        active_hours = {h: hour_lost.get(h, 0) / hour_total[h] * 100
                       for h in hour_total if hour_total[h] > 10}
        if active_hours:
            peak_hour = max(active_hours, key=active_hours.get)
            low_hour = min(active_hours, key=active_hours.get)
            if active_hours[peak_hour] > 3 * max(active_hours[low_hour], 0.01):
                print(f"\nStrong time-of-day correlation detected: "
                      f"worst hour is {peak_hour}:00 "
                      f"({active_hours[peak_hour]:.1f}% loss) vs "
                      f"best hour {low_hour}:00 "
                      f"({active_hours[low_hour]:.1f}% loss). "
                      f"This suggests shared congestion during peak usage.")


def find_bursts(entries):
    """Find consecutive sequences of lost packets."""
    bursts = []
    current = None
    for e in entries:
        if e["lost"]:
            if current is None:
                current = {
                    "start_epoch": e["epoch"],
                    "end_epoch": e["epoch"],
                    "length": 1,
                }
            else:
                current["end_epoch"] = e["epoch"]
                current["length"] += 1
        else:
            if current is not None:
                current["duration_ms"] = (
                    (current["end_epoch"] - current["start_epoch"]) * 1000
                )
                bursts.append(current)
                current = None
    if current is not None:
        current["duration_ms"] = (
            (current["end_epoch"] - current["start_epoch"]) * 1000
        )
        bursts.append(current)
    return bursts


def find_worst_windows(entries, window_sec=300):
    """Slide a time window across the data and find the worst periods."""
    if not entries:
        return []

    windows = []
    start_idx = 0
    epoch_key = lambda e: e["epoch"]

    for i in range(len(entries)):
        window_start = entries[i]["epoch"]
        window_end = window_start + window_sec

        # Find all entries in this window
        total = 0
        lost = 0
        for j in range(i, len(entries)):
            if entries[j]["epoch"] > window_end:
                break
            total += 1
            if entries[j]["lost"]:
                lost += 1

        if total > 0 and lost > 0:
            windows.append({
                "start": window_start,
                "total": total,
                "lost": lost,
                "loss_pct": lost / total * 100,
            })

    # Deduplicate overlapping windows — keep best per 5-min bucket
    if not windows:
        return []

    windows.sort(key=lambda w: -w["loss_pct"])
    seen_buckets = set()
    deduped = []
    for w in windows:
        bucket = int(w["start"] // window_sec)
        if bucket not in seen_buckets:
            seen_buckets.add(bucket)
            deduped.append(w)
        if len(deduped) >= 20:
            break

    return deduped


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Packet Loss Characterization Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = parser.add_subparsers(dest="mode", required=True)

    # Server
    srv = sub.add_parser("server", help="Run as echo server")
    srv.add_argument("--port", type=int, default=DEFAULT_PORT)

    # Client
    cli = sub.add_parser("client", help="Run as probe client")
    cli.add_argument("host", help="Server hostname or IP")
    cli.add_argument("--port", type=int, default=DEFAULT_PORT)
    cli.add_argument("--interval", type=int, default=DEFAULT_INTERVAL_MS,
                     metavar="MS", help="Probe interval in ms (default: 100)")
    cli.add_argument("--size", type=int, default=DEFAULT_PACKET_SIZE,
                     metavar="BYTES", help="Packet size in bytes (default: 128)")
    cli.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_MS,
                     metavar="MS", help="Loss timeout in ms (default: 2000)")
    cli.add_argument("--duration", type=int, default=None, metavar="SEC",
                     help="Run for N seconds then stop (default: until Ctrl-C)")
    cli.add_argument("--log", type=str, default=None, metavar="FILE",
                     help="Log file path (default: packetloss_TIMESTAMP.jsonl)")

    # Report
    rpt = sub.add_parser("report", help="Analyze a log file")
    rpt.add_argument("logfile", help="Path to .jsonl log file")

    args = parser.parse_args()

    if args.mode == "server":
        run_server(args.port)
    elif args.mode == "client":
        logfile = args.log
        if logfile is None:
            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            logfile = f"packetloss_{ts}.jsonl"
        run_client(args.host, args.port, args.interval, args.size,
                   args.timeout, args.duration, logfile)
    elif args.mode == "report":
        run_report(args.logfile)


if __name__ == "__main__":
    main()
