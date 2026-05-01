#!/usr/bin/env python3
"""ISP quality monitor — wraps mtr to track network path quality over time."""

import argparse
import csv
import json
import os
import signal
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone, timedelta

DB_DEFAULT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "isp_monitor.db")
TARGETS_DEFAULT = "8.8.8.8,1.1.1.1"
INTERVAL_DEFAULT = 60
PROBE_COUNT_DEFAULT = 10

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY,
    timestamp TEXT NOT NULL,
    target TEXT NOT NULL,
    probe_count INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS hops (
    id INTEGER PRIMARY KEY,
    run_id INTEGER NOT NULL REFERENCES runs(id),
    hop INTEGER NOT NULL,
    host TEXT,
    loss_pct REAL NOT NULL,
    sent INTEGER NOT NULL,
    last_ms REAL,
    avg_ms REAL,
    best_ms REAL,
    worst_ms REAL,
    stdev_ms REAL
);

CREATE INDEX IF NOT EXISTS idx_runs_timestamp ON runs(timestamp);
CREATE INDEX IF NOT EXISTS idx_runs_target ON runs(target);
CREATE INDEX IF NOT EXISTS idx_hops_run_id ON hops(run_id);
"""

_shutdown = False


def _handle_signal(signum, frame):
    global _shutdown
    _shutdown = True


def open_db(path):
    db = sqlite3.connect(path)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA foreign_keys=ON")
    db.executescript(SCHEMA)
    return db


def run_mtr(target, count):
    try:
        result = subprocess.run(
            ["mtr", "--json", "-c", str(count), target],
            capture_output=True, text=True, timeout=count * 10 + 30,
        )
    except FileNotFoundError:
        print("error: mtr not found in PATH", file=sys.stderr)
        return None
    except subprocess.TimeoutExpired:
        print(f"error: mtr timed out for {target}", file=sys.stderr)
        return None

    if result.returncode != 0:
        print(f"error: mtr exited {result.returncode} for {target}: {result.stderr.strip()}", file=sys.stderr)
        return None

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as e:
        print(f"error: failed to parse mtr output for {target}: {e}", file=sys.stderr)
        return None


def store_run(db, target, probe_count, mtr_data):
    ts = datetime.now(timezone.utc).isoformat()
    hubs = mtr_data.get("report", {}).get("hubs", [])
    if not hubs:
        return

    cur = db.execute(
        "INSERT INTO runs (timestamp, target, probe_count) VALUES (?, ?, ?)",
        (ts, target, probe_count),
    )
    run_id = cur.lastrowid

    for hub in hubs:
        db.execute(
            "INSERT INTO hops (run_id, hop, host, loss_pct, sent, last_ms, avg_ms, best_ms, worst_ms, stdev_ms) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                run_id,
                hub.get("count", 0),
                hub.get("host", "???"),
                hub.get("Loss%", 0.0),
                hub.get("Snt", 0),
                hub.get("Last", None),
                hub.get("Avg", None),
                hub.get("Best", None),
                hub.get("Wrst", None),
                hub.get("StDev", None),
            ),
        )

    db.commit()


def cmd_collect(args):
    targets = [t.strip() for t in args.targets.split(",")]
    db = open_db(args.db)

    print(f"ISP Monitor collecting", file=sys.stderr)
    print(f"  targets:  {', '.join(targets)}", file=sys.stderr)
    print(f"  interval: {args.interval}s", file=sys.stderr)
    print(f"  probes:   {args.count} per target per run", file=sys.stderr)
    print(f"  database: {args.db}", file=sys.stderr)

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    while not _shutdown:
        for target in targets:
            if _shutdown:
                break
            data = run_mtr(target, args.count)
            if data:
                store_run(db, target, args.count, data)

        if not _shutdown:
            deadline = time.monotonic() + args.interval
            while time.monotonic() < deadline and not _shutdown:
                time.sleep(min(1.0, deadline - time.monotonic()))

    print("\nshutting down...", file=sys.stderr)
    db.close()


def _parse_time(s):
    if s is None:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(s, fmt)
            return dt.replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            continue
    print(f"error: cannot parse time '{s}', use YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS", file=sys.stderr)
    sys.exit(1)


def _build_where(args):
    clauses = []
    params = []
    if hasattr(args, "from_time") and args.from_time:
        ts = _parse_time(args.from_time)
        clauses.append("r.timestamp >= ?")
        params.append(ts)
    if hasattr(args, "to_time") and args.to_time:
        ts = _parse_time(args.to_time)
        clauses.append("r.timestamp <= ?")
        params.append(ts)
    if hasattr(args, "target") and args.target:
        clauses.append("r.target = ?")
        params.append(args.target)
    if hasattr(args, "hop") and args.hop is not None:
        clauses.append("h.hop = ?")
        params.append(args.hop)
    where = " AND ".join(clauses)
    if where:
        where = "WHERE " + where
    return where, params


def cmd_report(args):
    db = open_db(args.db)
    where, params = _build_where(args)

    query = f"""
        SELECT datetime(r.timestamp, 'localtime'), r.target, h.hop, h.host, h.loss_pct,
               h.avg_ms, h.best_ms, h.worst_ms, h.stdev_ms, h.sent
        FROM hops h
        JOIN runs r ON h.run_id = r.id
        {where}
        ORDER BY r.timestamp, r.target, h.hop
    """
    rows = db.execute(query, params).fetchall()
    db.close()

    if not rows:
        print("No data found for the specified filters.", file=sys.stderr)
        return

    headers = ["timestamp", "target", "hop", "host", "loss_pct",
               "avg_ms", "best_ms", "worst_ms", "stdev_ms", "sent"]

    if args.format == "csv":
        writer = csv.writer(sys.stdout)
        writer.writerow(headers)
        writer.writerows(rows)
    else:
        fmt = "{:<26s} {:<15s} {:>3s} {:<45s} {:>6s} {:>8s} {:>8s} {:>8s} {:>8s} {:>4s}"
        print(fmt.format(*headers))
        print("-" * 140)
        for row in rows:
            ts, target, hop, host, loss, avg, best, worst, stdev, sent = row
            print(fmt.format(
                ts, target, str(hop), host or "???",
                f"{loss:.1f}", f"{avg:.1f}" if avg else "-",
                f"{best:.1f}" if best else "-", f"{worst:.1f}" if worst else "-",
                f"{stdev:.1f}" if stdev else "-", str(sent),
            ))


def cmd_summary(args):
    db = open_db(args.db)
    where, params = _build_where(args)

    # Basic stats
    row = db.execute(f"""
        SELECT COUNT(DISTINCT r.id), MIN(datetime(r.timestamp, 'localtime')), MAX(datetime(r.timestamp, 'localtime')),
               COUNT(DISTINCT r.target)
        FROM runs r
        JOIN hops h ON h.run_id = r.id
        {where}
    """, params).fetchone()

    total_runs, ts_min, ts_max, target_count = row
    if total_runs == 0:
        print("No data found.", file=sys.stderr)
        db.close()
        return

    print(f"=== ISP Monitor Summary ===\n")
    print(f"  Period:  {ts_min}  to  {ts_max}")
    print(f"  Runs:    {total_runs}")
    print(f"  Targets: {target_count}\n")

    # Per-target final-hop stats
    targets = db.execute(f"""
        SELECT DISTINCT r.target FROM runs r
        JOIN hops h ON h.run_id = r.id {where}
    """, params).fetchall()

    for (target,) in targets:
        t_params = params + [target]
        t_where = (where + " AND " if where else "WHERE ") + "r.target = ?"

        row = db.execute(f"""
            SELECT AVG(h.loss_pct), AVG(h.avg_ms),
                   MAX(h.avg_ms), MAX(h.worst_ms)
            FROM hops h
            JOIN runs r ON h.run_id = r.id
            {t_where}
            AND h.hop = (
                SELECT MAX(h2.hop) FROM hops h2
                JOIN runs r2 ON h2.run_id = r2.id
                WHERE r2.id = r.id
            )
        """, t_params).fetchone()

        avg_loss, avg_latency, max_avg_latency, max_worst = row
        print(f"  --- {target} (final hop) ---")
        print(f"    Avg loss:    {avg_loss:.2f}%")
        print(f"    Avg latency: {avg_latency:.1f} ms")
        print(f"    Max avg:     {max_avg_latency:.1f} ms")
        print(f"    Max worst:   {max_worst:.1f} ms")
        print()

    # Worst periods — 5-minute windows with highest loss
    print(f"  --- Worst 10 periods (by packet loss, any hop) ---")
    worst = db.execute(f"""
        SELECT datetime(r.timestamp, 'localtime'), r.target, h.hop, h.host, h.loss_pct, h.avg_ms
        FROM hops h
        JOIN runs r ON h.run_id = r.id
        {where}
        AND h.loss_pct > 0
        AND h.host != '???'
        ORDER BY h.loss_pct DESC, h.avg_ms DESC
        LIMIT 10
    """, params).fetchall()

    if worst:
        hw = max(len(host or '???') for _, _, _, host, *_ in worst)
        hw = max(hw, 4)
        print(f"    {'timestamp':<26s} {'target':<15s} {'hop':>3s} {'host':<{hw}s} {'loss%':>6s} {'avg_ms':>8s}")
        for ts, target, hop, host, loss, avg in worst:
            print(f"    {ts:<26s} {target:<15s} {hop:>3d} {(host or '???'):<{hw}s} {loss:>5.1f}% {avg or 0:>7.1f}")
    else:
        print("    No packet loss recorded.")
    print()

    # Per-hop breakdown — which hops contribute most loss
    print(f"  --- Per-hop loss summary (averaged across all runs) ---")
    hop_stats = db.execute(f"""
        SELECT h.hop, h.host, AVG(h.loss_pct), AVG(h.avg_ms),
               AVG(h.stdev_ms), COUNT(*)
        FROM hops h
        JOIN runs r ON h.run_id = r.id
        {where}
        GROUP BY h.hop, h.host
        HAVING AVG(h.loss_pct) > 0.0 OR AVG(h.avg_ms) > 0
        ORDER BY h.hop
    """, params).fetchall()

    if hop_stats:
        hw = max(len(host or '???') for _, host, *_ in hop_stats)
        hw = max(hw, 11)  # at least as wide as "no response"
        print(f"    {'hop':>3s} {'host':<{hw}s} {'loss%':>6s} {'avg_ms':>8s} {'jitter':>8s} {'samples':>8s}")
        for hop, host, loss, avg, stdev, count in hop_stats:
            display_host = "no response" if host == "???" else (host or "???")
            print(f"    {hop:>3d} {display_host:<{hw}s} {loss:>5.2f}% {avg or 0:>7.1f} {stdev or 0:>7.1f} {count:>8d}")
    print()

    # Hourly pattern
    print(f"  --- Hourly pattern (final hop, avg loss %) ---")
    hourly = db.execute(f"""
        SELECT CAST(strftime('%H', datetime(r.timestamp, 'localtime')) AS INTEGER) as hour,
               AVG(h.loss_pct), AVG(h.avg_ms)
        FROM hops h
        JOIN runs r ON h.run_id = r.id
        {where}
        AND h.hop = (
            SELECT MAX(h2.hop) FROM hops h2 WHERE h2.run_id = r.id
        )
        GROUP BY hour
        ORDER BY hour
    """, params).fetchall()

    if hourly:
        max_loss = max(h[1] for h in hourly) if hourly else 1
        for hour, loss, avg in hourly:
            bar_len = int((loss / max(max_loss, 0.01)) * 40) if max_loss > 0 else 0
            bar = "#" * bar_len
            print(f"    {hour:02d}:00  loss {loss:>5.2f}%  avg {avg:>6.1f}ms  {bar}")
    print()

    # Day-of-week pattern
    print(f"  --- Day-of-week pattern (final hop, avg loss %) ---")
    days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    daily = db.execute(f"""
        SELECT CAST(strftime('%w', datetime(r.timestamp, 'localtime')) AS INTEGER) as dow,
               AVG(h.loss_pct), AVG(h.avg_ms)
        FROM hops h
        JOIN runs r ON h.run_id = r.id
        {where}
        AND h.hop = (
            SELECT MAX(h2.hop) FROM hops h2 WHERE h2.run_id = r.id
        )
        GROUP BY dow
        ORDER BY dow
    """, params).fetchall()

    if daily:
        max_loss = max(d[1] for d in daily) if daily else 1
        for dow, loss, avg in daily:
            day_name = days[dow - 1] if 1 <= dow <= 7 else days[dow % 7]
            bar_len = int((loss / max(max_loss, 0.01)) * 40) if max_loss > 0 else 0
            bar = "#" * bar_len
            print(f"    {day_name}  loss {loss:>5.2f}%  avg {avg:>6.1f}ms  {bar}")
    print()

    db.close()


COLORS = [
    {"line": "rgba(99,202,255,1)", "fill": "rgba(99,202,255,0.15)"},
    {"line": "rgba(255,99,132,1)", "fill": "rgba(255,99,132,0.15)"},
    {"line": "rgba(75,192,132,1)", "fill": "rgba(75,192,132,0.15)"},
    {"line": "rgba(255,206,86,1)", "fill": "rgba(255,206,86,0.15)"},
]

HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ISP Monitor Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script src="https://cdn.jsdelivr.net/npm/chartjs-adapter-date-fns"></script>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { background: #0f0f1a; color: #d0d0d0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace; padding: 1.5rem; }
  h1 { color: #63caff; font-size: 1.5rem; margin-bottom: 1rem; }
  h2 { color: #8ab4f8; font-size: 1.1rem; margin-bottom: 0.75rem; }
  .banner { display: flex; flex-wrap: wrap; gap: 1rem; margin-bottom: 1.5rem; }
  .stat-card { background: #1a1a2e; border: 1px solid #2a2a4a; border-radius: 8px; padding: 1rem 1.25rem; min-width: 180px; flex: 1; }
  .stat-card .label { font-size: 0.75rem; color: #888; text-transform: uppercase; letter-spacing: 0.05em; }
  .stat-card .value { font-size: 1.4rem; color: #fff; margin-top: 0.25rem; }
  .stat-card .detail { font-size: 0.8rem; color: #999; margin-top: 0.25rem; }
  .chart-container { background: #1a1a2e; border: 1px solid #2a2a4a; border-radius: 8px; padding: 1.25rem; margin-bottom: 1.5rem; }
  .chart-wrap { position: relative; height: 300px; }
  table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
  th { background: #1e1e3a; color: #8ab4f8; text-align: left; padding: 0.5rem 0.75rem; position: sticky; top: 0; }
  td { padding: 0.4rem 0.75rem; border-bottom: 1px solid #2a2a4a; }
  tr:hover td { background: #1e1e3a; }
  .loss-ok { color: #4caf50; }
  .loss-warn { color: #ff9800; }
  .loss-bad { color: #f44336; font-weight: bold; }
  .latency-ok { color: #4caf50; }
  .latency-warn { color: #ff9800; }
  .latency-bad { color: #f44336; }
  .hop-no-response td { color: #555; font-style: italic; }
  footer { margin-top: 2rem; font-size: 0.75rem; color: #555; text-align: center; }
</style>
</head>
<body>
<h1>ISP Monitor Dashboard</h1>

<div class="banner" id="banner"></div>

<div class="chart-container">
  <h2>Final-Hop Latency Over Time</h2>
  <div class="chart-wrap"><canvas id="latencyChart"></canvas></div>
</div>

<div class="chart-container">
  <h2>Packet Loss Events</h2>
  <div class="chart-wrap"><canvas id="lossChart"></canvas></div>
</div>

<div class="chart-container">
  <h2>Hourly Pattern (Final Hop Averages)</h2>
  <div class="chart-wrap"><canvas id="hourlyChart"></canvas></div>
</div>

<div class="chart-container">
  <h2>Current Path (Latest Probe)</h2>
  <div id="hopTable"></div>
</div>

<footer>Generated: <span id="genTime"></span></footer>

<script>
const DATA = __DATA_JSON__;
const COLORS = __COLORS_JSON__;

document.getElementById('genTime').textContent = DATA.generated;

// --- Summary Banner ---
(function() {
  const el = document.getElementById('banner');
  const s = DATA.summary;
  const cards = [
    {label: 'Data Range', value: s.run_count + ' runs', detail: s.from + ' \\u2014 ' + s.to},
    {label: 'Targets', value: s.targets.length.toString(), detail: s.targets.join(', ')},
  ];
  s.per_target.forEach(function(t) {
    cards.push({
      label: t.target + ' avg',
      value: t.avg_latency.toFixed(1) + ' ms',
      detail: 'loss ' + t.avg_loss.toFixed(2) + '%  \\u00b7  worst ' + t.max_worst.toFixed(0) + ' ms'
    });
  });
  el.innerHTML = cards.map(function(c) {
    return '<div class="stat-card"><div class="label">' + c.label + '</div><div class="value">' + c.value + '</div><div class="detail">' + (c.detail||'') + '</div></div>';
  }).join('');
})();

// --- Latency Timeline ---
(function() {
  const targets = Object.keys(DATA.timeseries);
  const datasets = [];
  targets.forEach(function(t, i) {
    const c = COLORS[i % COLORS.length];
    const points = DATA.timeseries[t];
    datasets.push({
      label: t + ' avg',
      data: points.map(function(p) { return {x: p.ts, y: p.avg}; }),
      borderColor: c.line, backgroundColor: 'transparent',
      borderWidth: 1.5, pointRadius: 0, tension: 0.3,
    });
    datasets.push({
      label: t + ' worst',
      data: points.map(function(p) { return {x: p.ts, y: p.worst}; }),
      borderColor: c.line.replace('1)', '0.25)'), backgroundColor: c.fill,
      borderWidth: 0.5, pointRadius: 0, tension: 0.3, fill: '-1',
    });
  });
  new Chart(document.getElementById('latencyChart'), {
    type: 'line',
    data: {datasets: datasets},
    options: {
      responsive: true, maintainAspectRatio: false, animation: false,
      scales: {
        x: {type: 'time', grid: {color: '#2a2a4a'}, ticks: {color: '#888', maxTicksLimit: 12}},
        y: {title: {display: true, text: 'ms', color: '#888'}, grid: {color: '#2a2a4a'}, ticks: {color: '#888'}, beginAtZero: true}
      },
      plugins: {legend: {labels: {color: '#ccc', filter: function(item) { return item.text.indexOf('worst') === -1; }}}}
    }
  });
})();

// --- Loss Events ---
(function() {
  const targets = Object.keys(DATA.timeseries);
  const datasets = [];
  targets.forEach(function(t, i) {
    const c = COLORS[i % COLORS.length];
    const points = DATA.timeseries[t].filter(function(p) { return p.loss > 0; });
    datasets.push({
      label: t,
      data: points.map(function(p) { return {x: p.ts, y: p.loss}; }),
      backgroundColor: c.line, borderColor: c.line,
      pointRadius: points.map(function(p) { return Math.max(3, p.loss / 5); }),
      pointHoverRadius: 8, showLine: false,
    });
  });
  new Chart(document.getElementById('lossChart'), {
    type: 'scatter',
    data: {datasets: datasets},
    options: {
      responsive: true, maintainAspectRatio: false, animation: false,
      scales: {
        x: {type: 'time', grid: {color: '#2a2a4a'}, ticks: {color: '#888', maxTicksLimit: 12}},
        y: {title: {display: true, text: 'Loss %', color: '#888'}, grid: {color: '#2a2a4a'}, ticks: {color: '#888'}, beginAtZero: true}
      },
      plugins: {legend: {labels: {color: '#ccc'}}}
    }
  });
})();

// --- Hourly Pattern ---
(function() {
  const hours = Array.from({length: 24}, function(_, i) { return i; });
  const labels = hours.map(function(h) { return String(h).padStart(2, '0') + ':00'; });
  const datasets = [];
  DATA.hourly.forEach(function(h, i) {
    const c = COLORS[i % COLORS.length];
    const latMap = {};
    h.data.forEach(function(d) { latMap[d.hour] = d.avg; });
    datasets.push({
      label: h.target + ' latency',
      data: hours.map(function(hr) { return latMap[hr] || 0; }),
      backgroundColor: c.line.replace('1)', '0.6)'), borderColor: c.line, borderWidth: 1,
      yAxisID: 'y',
    });
    var lossMap = {};
    h.data.forEach(function(d) { lossMap[d.hour] = d.loss; });
    datasets.push({
      label: h.target + ' loss %',
      data: hours.map(function(hr) { return lossMap[hr] || 0; }),
      type: 'line', borderColor: c.line, backgroundColor: 'transparent',
      borderWidth: 2, borderDash: [5, 3], pointRadius: 2, tension: 0.3,
      yAxisID: 'y1',
    });
  });
  new Chart(document.getElementById('hourlyChart'), {
    type: 'bar',
    data: {labels: labels, datasets: datasets},
    options: {
      responsive: true, maintainAspectRatio: false, animation: false,
      scales: {
        x: {grid: {color: '#2a2a4a'}, ticks: {color: '#888'}},
        y: {position: 'left', title: {display: true, text: 'Avg ms', color: '#888'}, grid: {color: '#2a2a4a'}, ticks: {color: '#888'}, beginAtZero: true},
        y1: {position: 'right', title: {display: true, text: 'Loss %', color: '#888'}, grid: {drawOnChartArea: false}, ticks: {color: '#888'}, beginAtZero: true}
      },
      plugins: {legend: {labels: {color: '#ccc'}}}
    }
  });
})();

// --- Hop Table ---
(function() {
  const el = document.getElementById('hopTable');
  if (!DATA.latest_hops || DATA.latest_hops.length === 0) {
    el.innerHTML = '<p style="color:#888">No hop data available.</p>';
    return;
  }
  function lossClass(v) { return v <= 0 ? 'loss-ok' : v < 5 ? 'loss-warn' : 'loss-bad'; }
  function latClass(v) { if (v === null) return ''; return v < 50 ? 'latency-ok' : v < 150 ? 'latency-warn' : 'latency-bad'; }
  function fmt(v) { return v === null ? '-' : v.toFixed(1); }

  let html = '<table><thead><tr><th>Target</th><th>Hop</th><th>Host</th><th>Loss %</th><th>Avg ms</th><th>Best ms</th><th>Worst ms</th><th>StDev</th></tr></thead><tbody>';
  DATA.latest_hops.forEach(function(h) {
    var noResp = !h.host || h.host === '???';
    var rowClass = noResp ? ' class="hop-no-response"' : '';
    var hostDisplay = noResp ? 'no response' : h.host;
    if (noResp) {
      html += '<tr' + rowClass + '><td>' + h.target + '</td><td>' + h.hop + '</td><td>' + hostDisplay +
              '</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td></tr>';
    } else {
      html += '<tr><td>' + h.target + '</td><td>' + h.hop + '</td><td>' + hostDisplay +
              '</td><td class="' + lossClass(h.loss) + '">' + h.loss.toFixed(1) + '%</td>' +
              '<td class="' + latClass(h.avg) + '">' + fmt(h.avg) + '</td>' +
              '<td>' + fmt(h.best) + '</td><td>' + fmt(h.worst) + '</td>' +
              '<td>' + fmt(h.stdev) + '</td></tr>';
    }
  });
  html += '</tbody></table>';
  el.innerHTML = html;
})();
</script>
</body>
</html>
"""


def cmd_html(args):
    db = open_db(args.db)

    if not args.from_time:
        args.from_time = (datetime.now(timezone.utc) - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%S")

    where, params = _build_where(args)

    # Summary stats
    row = db.execute(f"""
        SELECT COUNT(DISTINCT r.id), MIN(datetime(r.timestamp, 'localtime')), MAX(datetime(r.timestamp, 'localtime'))
        FROM runs r JOIN hops h ON h.run_id = r.id {where}
    """, params).fetchone()

    run_count, ts_min, ts_max = row
    if run_count == 0:
        print("No data found for the specified filters.", file=sys.stderr)
        db.close()
        return

    targets = [r[0] for r in db.execute(f"""
        SELECT DISTINCT r.target FROM runs r JOIN hops h ON h.run_id = r.id {where}
    """, params).fetchall()]

    per_target = []
    for target in targets:
        t_params = params + [target]
        t_where = (where + " AND " if where else "WHERE ") + "r.target = ?"
        row = db.execute(f"""
            SELECT AVG(h.loss_pct), AVG(h.avg_ms), MAX(h.worst_ms)
            FROM hops h JOIN runs r ON h.run_id = r.id
            {t_where}
            AND h.hop = (SELECT MAX(h2.hop) FROM hops h2 WHERE h2.run_id = r.id)
        """, t_params).fetchone()
        per_target.append({
            "target": target,
            "avg_loss": row[0] or 0,
            "avg_latency": row[1] or 0,
            "max_worst": row[2] or 0,
        })

    summary = {
        "run_count": run_count,
        "from": ts_min,
        "to": ts_max,
        "targets": targets,
        "per_target": per_target,
    }

    # Time series: final-hop data per run
    timeseries = {}
    for target in targets:
        t_params = params + [target]
        t_where = (where + " AND " if where else "WHERE ") + "r.target = ?"
        rows = db.execute(f"""
            SELECT datetime(r.timestamp, 'localtime'), h.avg_ms, h.worst_ms, h.loss_pct
            FROM hops h JOIN runs r ON h.run_id = r.id
            {t_where}
            AND h.hop = (SELECT MAX(h2.hop) FROM hops h2 WHERE h2.run_id = r.id)
            ORDER BY r.timestamp
        """, t_params).fetchall()
        timeseries[target] = [
            {"ts": r[0], "avg": r[1], "worst": r[2], "loss": r[3]}
            for r in rows
        ]

    # Hourly pattern
    hourly = []
    for target in targets:
        t_params = params + [target]
        t_where = (where + " AND " if where else "WHERE ") + "r.target = ?"
        rows = db.execute(f"""
            SELECT CAST(strftime('%H', datetime(r.timestamp, 'localtime')) AS INTEGER) as hour,
                   AVG(h.loss_pct), AVG(h.avg_ms)
            FROM hops h JOIN runs r ON h.run_id = r.id
            {t_where}
            AND h.hop = (SELECT MAX(h2.hop) FROM hops h2 WHERE h2.run_id = r.id)
            GROUP BY hour ORDER BY hour
        """, t_params).fetchall()
        hourly.append({
            "target": target,
            "data": [{"hour": r[0], "loss": r[1] or 0, "avg": r[2] or 0} for r in rows],
        })

    # Latest hop-by-hop path per target
    latest_hops = []
    for target in targets:
        row = db.execute("""
            SELECT id FROM runs WHERE target = ? ORDER BY timestamp DESC LIMIT 1
        """, (target,)).fetchone()
        if row:
            hops = db.execute("""
                SELECT hop, host, loss_pct, avg_ms, best_ms, worst_ms, stdev_ms
                FROM hops WHERE run_id = ? ORDER BY hop
            """, (row[0],)).fetchall()
            for h in hops:
                latest_hops.append({
                    "target": target,
                    "hop": h[0], "host": h[1],
                    "loss": h[2], "avg": h[3], "best": h[4],
                    "worst": h[5], "stdev": h[6],
                })

    db.close()

    data = {
        "generated": datetime.now().astimezone().isoformat(),
        "summary": summary,
        "timeseries": timeseries,
        "hourly": hourly,
        "latest_hops": latest_hops,
    }

    html = HTML_TEMPLATE.replace("__DATA_JSON__", json.dumps(data))
    html = html.replace("__COLORS_JSON__", json.dumps(COLORS))

    with open(args.output, "w") as f:
        f.write(html)

    print(f"Dashboard written to {args.output}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        description="ISP quality monitor — wraps mtr to track network path quality over time"
    )
    sub = parser.add_subparsers(dest="command")

    # collect
    p_collect = sub.add_parser("collect", help="Run mtr probes and store results")
    p_collect.add_argument("--db", default=DB_DEFAULT, help="SQLite database path")
    p_collect.add_argument("--interval", type=int, default=INTERVAL_DEFAULT,
                           help="Seconds between probe rounds (default: 60)")
    p_collect.add_argument("--targets", default=TARGETS_DEFAULT,
                           help="Comma-separated targets (default: 8.8.8.8,1.1.1.1)")
    p_collect.add_argument("--count", type=int, default=PROBE_COUNT_DEFAULT,
                           help="Number of mtr probes per target (default: 10)")

    # report
    p_report = sub.add_parser("report", help="Export collected data")
    p_report.add_argument("--db", default=DB_DEFAULT, help="SQLite database path")
    p_report.add_argument("--from", dest="from_time", help="Start time (YYYY-MM-DD or ISO)")
    p_report.add_argument("--to", dest="to_time", help="End time (YYYY-MM-DD or ISO)")
    p_report.add_argument("--format", choices=["csv", "text"], default="text",
                           help="Output format (default: text)")
    p_report.add_argument("--target", help="Filter by target")
    p_report.add_argument("--hop", type=int, help="Filter by hop number")

    # summary
    p_summary = sub.add_parser("summary", help="Show summary statistics")
    p_summary.add_argument("--db", default=DB_DEFAULT, help="SQLite database path")
    p_summary.add_argument("--from", dest="from_time", help="Start time (YYYY-MM-DD or ISO)")
    p_summary.add_argument("--to", dest="to_time", help="End time (YYYY-MM-DD or ISO)")
    p_summary.add_argument("--target", help="Filter by target")

    # html
    p_html = sub.add_parser("html", help="Generate a static HTML dashboard")
    p_html.add_argument("--db", default=DB_DEFAULT, help="SQLite database path")
    p_html.add_argument("--from", dest="from_time",
                        help="Start time (default: 24 hours ago)")
    p_html.add_argument("--to", dest="to_time", help="End time")
    p_html.add_argument("--target", help="Filter by target")
    p_html.add_argument("--output", required=True,
                        help="Output HTML file path")

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(1)

    if args.command == "collect":
        cmd_collect(args)
    elif args.command == "report":
        cmd_report(args)
    elif args.command == "summary":
        cmd_summary(args)
    elif args.command == "html":
        cmd_html(args)


if __name__ == "__main__":
    main()
