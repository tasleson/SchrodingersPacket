#!/usr/bin/env python3
"""
Packet Loss Characterization Tool

A combined client/server program that measures and characterizes UDP packet
loss between two endpoints. Produces detailed reports suitable for filing
complaints with an ISP about degraded service.

Usage:
    Server:  python3 packetloss.py server [--port 5201]
    Client:  python3 packetloss.py client <server_host> [options]
    Report:  python3 packetloss.py report <logfile> [logfile ...]
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

# Log file format: 8-byte file magic, then a stream of fixed 16-byte records.
# Record layout: uint32 seq, double epoch, float32 rtt_ms.
# A NaN rtt_ms marks a lost packet (no real RTT could ever be NaN).
LOG_MAGIC = b"PLCTLOG\x01"
LOG_RECORD_FMT = "<Idf"
LOG_RECORD_SIZE = struct.calcsize(LOG_RECORD_FMT)

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
        new_file = (not os.path.exists(logfile)) or os.path.getsize(logfile) == 0
        log_fh = open(logfile, "ab")
        if new_file:
            log_fh.write(LOG_MAGIC)
            log_fh.flush()
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
    rtt_ms = float("nan") if result["lost"] else result["rtt_ms"]
    fh.write(struct.pack(LOG_RECORD_FMT, result["seq"], result["send_ts"], rtt_ms))
    fh.flush()


def iter_log(logfile):
    """Yield entry dicts from a log file. Reads the binary format, with a
    fallback to legacy JSONL so older logs still work with `report`."""
    with open(logfile, "rb") as fh:
        magic = fh.read(len(LOG_MAGIC))
        if magic == LOG_MAGIC:
            buf = fh.read()
            isnan = math.isnan
            for seq, epoch, rtt_ms in struct.iter_unpack(LOG_RECORD_FMT, buf):
                lost = isnan(rtt_ms)
                yield {
                    "seq": seq,
                    "epoch": epoch,
                    "rtt_ms": None if lost else float(rtt_ms),
                    "lost": lost,
                }
            return
        fh.seek(0)
        for raw in fh:
            line = raw.strip()
            if line:
                yield json.loads(line)


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

def run_report(logfiles):
    entries = []
    bursts = []
    for logfile in logfiles:
        if not os.path.exists(logfile):
            print(f"Error: {logfile} not found", file=sys.stderr)
            sys.exit(1)
        file_entries = list(iter_log(logfile))
        if not file_entries:
            continue
        # Sort within a file by seq so bursts are detected against the original
        # send order. Cross-file seq numbers can collide, so we don't sort the
        # combined list by seq.
        file_entries.sort(key=lambda e: e["seq"])
        bursts.extend(find_bursts(file_entries))
        entries.extend(file_entries)

    if not entries:
        print("No data in log file(s).")
        return

    # Aggregate analysis runs across files; order chronologically by timestamp.
    entries.sort(key=lambda e: e["epoch"])
    bursts.sort(key=lambda b: b["start_epoch"])

    total = len(entries)
    lost_entries = [e for e in entries if e["lost"]]
    recv_entries = [e for e in entries if not e["lost"]]
    loss_pct = len(lost_entries) / total * 100 if total else 0

    first_ts = datetime.datetime.fromtimestamp(entries[0]["epoch"])
    last_ts = datetime.datetime.fromtimestamp(entries[-1]["epoch"])
    duration = last_ts - first_ts

    # Call-killing windows: 30s with >=5% loss. Computed up front so the
    # total count can appear in the summary, then reused for the detail
    # section further down.
    vc_window_sec = 30
    vc_loss_threshold = 5.0
    vc_min_total = 20
    all_vc_windows = [
        w for w in find_worst_windows(
            entries,
            window_sec=vc_window_sec,
            top_n=None,
            min_total=vc_min_total,
        )
        if w["loss_pct"] >= vc_loss_threshold
    ]

    print("=" * 70)
    print("PACKET LOSS CHARACTERIZATION REPORT")
    print("=" * 70)
    if len(logfiles) == 1:
        print(f"Log file:       {logfiles[0]}")
    else:
        print(f"Log files:      {len(logfiles)} files")
        for lf in logfiles:
            print(f"                  {lf}")
    print(f"Period:         {first_ts.strftime('%Y-%m-%d %H:%M:%S')} to "
          f"{last_ts.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Duration:       {duration}")
    print(f"Total probes:   {total}")
    print(f"Received:       {len(recv_entries)}")
    print(f"Lost:           {len(lost_entries)}")
    print(f"Overall loss:   {loss_pct:.2f}%")
    print(f"Video call-killing windows ({vc_window_sec}s, >={vc_loss_threshold:.0f}% "
          f"loss): {len(all_vc_windows)}")

    print_trend_summary(entries)

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
    day_total = collections.Counter()
    day_lost = collections.Counter()
    weekday_names = ["Monday", "Tuesday", "Wednesday", "Thursday",
                     "Friday", "Saturday", "Sunday"]
    localtime = time.localtime
    for e in entries:
        tm = localtime(e["epoch"])
        h = tm.tm_hour
        d = weekday_names[tm.tm_wday]
        hour_total[h] += 1
        day_total[d] += 1
        if e["lost"]:
            hour_lost[h] += 1
            day_lost[d] += 1

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
    print(f"{'Day':>12}  {'Total':>8}  {'Lost':>8}  {'Loss%':>8}  Bar")
    for d in weekday_names:
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

    # --- Video-conference call killer windows ---
    print("\n" + "-" * 70)
    print(f"TOP 25 CALL-KILLING WINDOWS ({vc_window_sec}s, "
          f">={vc_loss_threshold:.0f}% loss — would tank a video call)")
    print("-" * 70)
    if all_vc_windows:
        print(f"{'Start Time':>22}  {'Day':>10}  {'Total':>7}  "
              f"{'Lost':>6}  {'Loss%':>7}")
        for w in all_vc_windows[:25]:
            ts = datetime.datetime.fromtimestamp(w["start"])
            print(f"{ts.strftime('%Y-%m-%d %H:%M:%S'):>22}  "
                  f"{ts.strftime('%A'):>10}  {w['total']:>7}  "
                  f"{w['lost']:>6}  {w['loss_pct']:>6.2f}%")
    else:
        print(f"No {vc_window_sec}-second windows exceeded "
              f"{vc_loss_threshold:.0f}% loss — calls would have held up.")

    # --- RTT over time (hourly) ---
    if recv_entries:
        print("\n" + "-" * 70)
        print("AVERAGE RTT BY HOUR OF DAY (ms)")
        print("-" * 70)
        hour_rtts = collections.defaultdict(list)
        for e in recv_entries:
            hour_rtts[localtime(e["epoch"]).tm_hour].append(e["rtt_ms"])
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


def daily_loss_summary(entries, max_days=7):
    """Group entries by local calendar date and compute per-day loss stats.
    Returns chronologically ordered per-day stats for up to the most recent
    `max_days` calendar days that contain data."""
    by_date = {}
    localtime = time.localtime
    for e in entries:
        tm = localtime(e["epoch"])
        d = datetime.date(tm.tm_year, tm.tm_mon, tm.tm_mday)
        bucket = by_date.get(d)
        if bucket is None:
            bucket = {"total": 0, "lost": 0}
            by_date[d] = bucket
        bucket["total"] += 1
        if e["lost"]:
            bucket["lost"] += 1

    dates = sorted(by_date.keys())
    if len(dates) > max_days:
        dates = dates[-max_days:]

    return [
        {
            "date": d,
            "total": by_date[d]["total"],
            "lost": by_date[d]["lost"],
            "loss_pct": (by_date[d]["lost"] / by_date[d]["total"] * 100)
                        if by_date[d]["total"] else 0.0,
        }
        for d in dates
    ]


def print_trend_summary(entries):
    daily = daily_loss_summary(entries, max_days=7)
    print("\n" + "-" * 70)
    print(f"RECENT DAILY TREND (last {len(daily)} day(s) with data)")
    print("-" * 70)

    if not daily:
        print("No daily data.")
        return

    print(f"  {'Date':<15} {'Loss%':>7}  {'Lost/Total':>16}  Bar")
    for d in daily:
        bar = "█" * int(d["loss_pct"] * 2)
        date_str = d["date"].strftime("%Y-%m-%d %a")
        ratio = f"{d['lost']}/{d['total']}"
        print(f"  {date_str:<15} {d['loss_pct']:>6.2f}%  {ratio:>16}  {bar}")

    if len(daily) < 2:
        print("\n  Trend: insufficient data (need at least 2 days).")
        return

    n = len(daily)
    xs = list(range(n))
    ys = [d["loss_pct"] for d in daily]
    mean_x = sum(xs) / n
    mean_y = sum(ys) / n
    num = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys))
    den = sum((x - mean_x) ** 2 for x in xs)
    slope = num / den if den else 0.0
    net_change = slope * (n - 1)

    # Classify as HOLDING if either the absolute net change across the window
    # is tiny (< 0.1 percentage points) or it's small relative to the mean
    # (< 20%). Otherwise the sign of the slope decides direction.
    abs_thresh = 0.1
    rel_thresh = 0.20
    if (abs(net_change) < abs_thresh
            or (mean_y > 0 and abs(net_change) / mean_y < rel_thresh)):
        verdict = "HOLDING"
    elif slope > 0:
        verdict = "INCREASING"
    else:
        verdict = "DECREASING"

    print(f"\n  Trend: {verdict}  "
          f"(slope {slope:+.3f}%/day, net {net_change:+.2f}% over window)")


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


def find_worst_windows(entries, window_sec=300, top_n=20, min_total=1):
    """Slide a time window across the data and find the worst periods.

    Windows are deduplicated to one per non-overlapping bucket of width
    `window_sec`, then the top `top_n` by loss percentage are returned.
    Pass `top_n=None` to return every distinct bucket. `min_total` filters
    out windows that don't have enough samples to be meaningful (e.g. tiny
    tail-end windows).
    """
    if not entries:
        return []

    n = len(entries)
    windows = []
    right = 0
    total = 0
    lost = 0

    for left in range(n):
        window_end = entries[left]["epoch"] + window_sec
        while right < n and entries[right]["epoch"] <= window_end:
            total += 1
            if entries[right]["lost"]:
                lost += 1
            right += 1

        if total >= min_total and lost > 0:
            windows.append({
                "start": entries[left]["epoch"],
                "total": total,
                "lost": lost,
                "loss_pct": lost / total * 100,
            })

        total -= 1
        if entries[left]["lost"]:
            lost -= 1

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
        if top_n is not None and len(deduped) >= top_n:
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
                     help="Log file path (default: packetloss_TIMESTAMP.plct)")

    # Report
    rpt = sub.add_parser("report", help="Analyze one or more log files")
    rpt.add_argument("logfile", nargs="+",
                     help="Path to one or more log files (combined into a single report)")

    args = parser.parse_args()

    if args.mode == "server":
        run_server(args.port)
    elif args.mode == "client":
        logfile = args.log
        if logfile is None:
            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            logfile = f"packetloss_{ts}.plct"
        run_client(args.host, args.port, args.interval, args.size,
                   args.timeout, args.duration, logfile)
    elif args.mode == "report":
        run_report(args.logfile)  # nargs="+" → list


if __name__ == "__main__":
    main()
