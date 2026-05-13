"""
app.py
Flask web dashboard — serves the SOC alert dashboard.
Run: python app.py
Open: http://localhost:5000
"""

from flask import Flask, render_template_string, jsonify
import json
import os

app = Flask(__name__)

ALERTS_FILE = "alerts.json"

def load_alerts():
    if not os.path.exists(ALERTS_FILE):
        return []
    with open(ALERTS_FILE) as f:
        return json.load(f)

def get_stats(alerts):
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    mitre_counts    = {}
    ip_counts       = {}

    for a in alerts:
        severity_counts[a["severity"]] = severity_counts.get(a["severity"], 0) + 1
        mitre_counts[a["mitre_id"]]    = mitre_counts.get(a["mitre_id"], 0) + 1
        ip_counts[a["source_ip"]]      = ip_counts.get(a["source_ip"], 0) + 1

    top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    return severity_counts, mitre_counts, top_ips

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SOC Alert Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'Segoe UI', Arial, sans-serif; background: #0f1117; color: #e2e8f0; min-height: 100vh; }
  .topbar { background: #1a1d2e; border-bottom: 1px solid #2d3748; padding: 14px 28px; display: flex; align-items: center; justify-content: space-between; }
  .topbar h1 { font-size: 18px; font-weight: 600; color: #63b3ed; letter-spacing: 0.5px; }
  .live-badge { background: #276749; color: #9ae6b4; font-size: 11px; padding: 3px 10px; border-radius: 99px; font-weight: 500; }
  .container { padding: 24px 28px; max-width: 1400px; }
  .stat-row { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin-bottom: 24px; }
  .stat-card { border-radius: 10px; padding: 18px 20px; }
  .stat-card.critical { background: #2d1515; border: 1px solid #c53030; }
  .stat-card.high     { background: #2d1f00; border: 1px solid #c05621; }
  .stat-card.medium   { background: #2d2600; border: 1px solid #b7791f; }
  .stat-card.low      { background: #0d2137; border: 1px solid #2b6cb0; }
  .stat-num  { font-size: 36px; font-weight: 700; margin-bottom: 4px; }
  .stat-card.critical .stat-num { color: #fc8181; }
  .stat-card.high     .stat-num { color: #f6ad55; }
  .stat-card.medium   .stat-num { color: #f6e05e; }
  .stat-card.low      .stat-num { color: #63b3ed; }
  .stat-lbl  { font-size: 12px; color: #a0aec0; text-transform: uppercase; letter-spacing: 0.5px; }
  .charts-row { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; margin-bottom: 24px; }
  .chart-card { background: #1a1d2e; border: 1px solid #2d3748; border-radius: 10px; padding: 18px 20px; }
  .chart-card h3 { font-size: 13px; color: #a0aec0; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 16px; }
  canvas { max-height: 200px; }
  .alerts-section h2 { font-size: 14px; color: #a0aec0; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 12px; }
  table { width: 100%; border-collapse: collapse; background: #1a1d2e; border-radius: 10px; overflow: hidden; border: 1px solid #2d3748; font-size: 13px; }
  th { background: #2d3748; color: #a0aec0; font-weight: 500; padding: 10px 14px; text-align: left; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; }
  td { padding: 10px 14px; border-bottom: 1px solid #2d3748; color: #e2e8f0; vertical-align: top; }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: #2d3748; }
  .sev { display: inline-block; font-size: 11px; padding: 2px 8px; border-radius: 99px; font-weight: 600; }
  .sev-Critical { background: #2d1515; color: #fc8181; border: 1px solid #c53030; }
  .sev-High     { background: #2d1f00; color: #f6ad55; border: 1px solid #c05621; }
  .sev-Medium   { background: #2d2600; color: #f6e05e; border: 1px solid #b7791f; }
  .sev-Low      { background: #0d2137; color: #63b3ed; border: 1px solid #2b6cb0; }
  .mitre { font-size: 11px; color: #9f7aea; font-family: monospace; }
  .desc  { color: #a0aec0; font-size: 12px; }
  .refresh-btn { background: #2b6cb0; color: white; border: none; padding: 8px 16px; border-radius: 6px; font-size: 13px; cursor: pointer; margin-bottom: 16px; }
  .refresh-btn:hover { background: #2c5282; }
  .empty { text-align: center; padding: 40px; color: #4a5568; }
</style>
</head>
<body>

<div class="topbar">
  <h1>⬡ SOC Alert Dashboard</h1>
  <span class="live-badge">● MONITORING ACTIVE</span>
</div>

<div class="container">
  <div class="stat-row">
    <div class="stat-card critical">
      <div class="stat-num">{{ stats.critical }}</div>
      <div class="stat-lbl">Critical</div>
    </div>
    <div class="stat-card high">
      <div class="stat-num">{{ stats.high }}</div>
      <div class="stat-lbl">High</div>
    </div>
    <div class="stat-card medium">
      <div class="stat-num">{{ stats.medium }}</div>
      <div class="stat-lbl">Medium</div>
    </div>
    <div class="stat-card low">
      <div class="stat-num">{{ stats.low }}</div>
      <div class="stat-lbl">Low</div>
    </div>
  </div>

  <div class="charts-row">
    <div class="chart-card">
      <h3>Alerts by Severity</h3>
      <canvas id="sevChart"></canvas>
    </div>
    <div class="chart-card">
      <h3>Top Threat Sources (IPs)</h3>
      <canvas id="ipChart"></canvas>
    </div>
  </div>

  <div class="alerts-section">
    <h2>Alert Triage Queue — {{ total }} alerts</h2>
    <button class="refresh-btn" onclick="location.reload()">↻ Refresh</button>

    {% if alerts %}
    <table>
      <thead>
        <tr>
          <th>#</th>
          <th>Severity</th>
          <th>MITRE</th>
          <th>Alert</th>
          <th>Source IP</th>
          <th>User</th>
          <th>Description</th>
          <th>Time</th>
        </tr>
      </thead>
      <tbody>
        {% for a in alerts | sort(attribute='severity', reverse=False) %}
        <tr>
          <td>{{ a.id }}</td>
          <td><span class="sev sev-{{ a.severity }}">{{ a.severity }}</span></td>
          <td><span class="mitre">{{ a.mitre_id }}</span></td>
          <td>{{ a.title }}</td>
          <td><code style="font-size:12px; color:#68d391;">{{ a.source_ip }}</code></td>
          <td>{{ a.user }}</td>
          <td class="desc">{{ a.description }}</td>
          <td style="font-size:11px; color:#718096; white-space:nowrap;">{{ a.timestamp }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
    {% else %}
    <div class="empty">
      <p>No alerts found. Run <code>python detect.py</code> first.</p>
    </div>
    {% endif %}
  </div>
</div>

<script>
const sevData = {
  labels: ['Critical', 'High', 'Medium', 'Low'],
  datasets: [{
    data: [{{ stats.critical }}, {{ stats.high }}, {{ stats.medium }}, {{ stats.low }}],
    backgroundColor: ['#c53030','#c05621','#b7791f','#2b6cb0'],
    borderWidth: 0,
  }]
};
new Chart(document.getElementById('sevChart'), {
  type: 'doughnut',
  data: sevData,
  options: { plugins: { legend: { labels: { color: '#a0aec0', font: { size: 12 } } } }, cutout: '65%' }
});

const ipLabels = {{ top_ip_labels | tojson }};
const ipValues = {{ top_ip_values | tojson }};
new Chart(document.getElementById('ipChart'), {
  type: 'bar',
  data: {
    labels: ipLabels,
    datasets: [{ label: 'Alerts', data: ipValues, backgroundColor: '#2b6cb0', borderRadius: 4 }]
  },
  options: {
    indexAxis: 'y',
    plugins: { legend: { display: false } },
    scales: {
      x: { ticks: { color: '#a0aec0' }, grid: { color: '#2d3748' } },
      y: { ticks: { color: '#a0aec0', font: { size: 11 } }, grid: { display: false } }
    }
  }
});
</script>
</body>
</html>
"""

@app.route("/")
def dashboard():
    alerts = load_alerts()
    severity_counts, mitre_counts, top_ips = get_stats(alerts)

    stats = {
        "critical": severity_counts.get("Critical", 0),
        "high":     severity_counts.get("High", 0),
        "medium":   severity_counts.get("Medium", 0),
        "low":      severity_counts.get("Low", 0),
    }

    top_ip_labels = [ip for ip, _ in top_ips]
    top_ip_values = [count for _, count in top_ips]

    return render_template_string(
        DASHBOARD_HTML,
        alerts        = alerts,
        stats         = stats,
        total         = len(alerts),
        top_ip_labels = top_ip_labels,
        top_ip_values = top_ip_values,
    )

@app.route("/api/alerts")
def api_alerts():
    return jsonify(load_alerts())

@app.route("/api/stats")
def api_stats():
    alerts = load_alerts()
    severity_counts, mitre_counts, top_ips = get_stats(alerts)
    return jsonify({
        "total":           len(alerts),
        "severity_counts": severity_counts,
        "mitre_counts":    mitre_counts,
        "top_ips":         top_ips,
    })

if __name__ == "__main__":
    print("\n[✓] SOC Dashboard starting...")
    print("[→] Open in browser: http://localhost:5000\n")
    app.run(debug=True, port=5000)
