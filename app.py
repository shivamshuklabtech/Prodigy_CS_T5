"""
Packet Pulse — Network Packet Analyzer
A single-file Flask app: Python backend (using scapy) sniffs packets on
your own machine/network interface and a browser frontend displays them
live — source/destination IP, protocol, length, and a payload preview.

Ethical use note:
Only run this on networks and interfaces you own or have explicit
permission to monitor (e.g. your own laptop's traffic). Capturing traffic
on networks you don't control or don't have permission for is illegal in
most places. This tool is for learning how packet capture and protocol
parsing work.

Setup:
    pip install flask scapy --break-system-packages

Run (packet sniffing needs elevated privileges):
    python app.py

Then open http://127.0.0.1:5000
"""

import threading
import time
import datetime
from collections import deque

from flask import Flask, jsonify, render_template_string

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
except ImportError:
    raise SystemExit(
        "scapy is required. Install it with:\n"
        "  pip install scapy --break-system-packages"
    )

app = Flask(__name__)

MAX_PACKETS = 200
packet_log = deque(maxlen=MAX_PACKETS)
log_lock = threading.Lock()
capture_state = {"running": False, "count": 0}


def protocol_name(pkt):
    if pkt.haslayer(TCP):
        return "TCP"
    if pkt.haslayer(UDP):
        return "UDP"
    if pkt.haslayer(ICMP):
        return "ICMP"
    return "OTHER"


def payload_preview(pkt, max_len=48):
    if pkt.haslayer(Raw):
        raw = bytes(pkt[Raw].load)
        try:
            text = raw.decode("utf-8", errors="replace")
        except Exception:
            text = repr(raw)
        text = text.replace("\n", "\\n").replace("\r", "")
        return text[:max_len] + ("…" if len(text) > max_len else "")
    return ""


def handle_packet(pkt):
    if not pkt.haslayer(IP):
        return
    ip_layer = pkt[IP]
    entry = {
        "time": datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3],
        "src": ip_layer.src,
        "dst": ip_layer.dst,
        "proto": protocol_name(pkt),
        "length": len(pkt),
        "payload": payload_preview(pkt),
    }
    if pkt.haslayer(TCP):
        entry["sport"] = pkt[TCP].sport
        entry["dport"] = pkt[TCP].dport
    elif pkt.haslayer(UDP):
        entry["sport"] = pkt[UDP].sport
        entry["dport"] = pkt[UDP].dport

    with log_lock:
        packet_log.appendleft(entry)
        capture_state["count"] += 1


def sniff_loop():
    capture_state["running"] = True
    try:
        sniff(prn=handle_packet, store=False,
              stop_filter=lambda p: not capture_state["running"])
    finally:
        capture_state["running"] = False


@app.route("/api/start", methods=["POST"])
def api_start():
    if not capture_state["running"]:
        t = threading.Thread(target=sniff_loop, daemon=True)
        t.start()
        time.sleep(0.3)  # give sniff() a moment to attach
    return jsonify({"running": capture_state["running"]})


@app.route("/api/stop", methods=["POST"])
def api_stop():
    capture_state["running"] = False
    return jsonify({"running": capture_state["running"]})


@app.route("/api/packets")
def api_packets():
    with log_lock:
        return jsonify({
            "running": capture_state["running"],
            "count": capture_state["count"],
            "packets": list(packet_log)[:100],
        })


@app.route("/")
def index():
    return render_template_string(PAGE_TEMPLATE)


PAGE_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>Packet Pulse — Network Analyzer</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght@9..144,400;9..144,600;9..144,700&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
<style>
  :root{
    --charcoal:#10141a; --charcoal-2:#171c24; --teal:#3fb8af; --amber:#d9a441;
    --bone:#e9edf2; --bone-dim:#8b95a3; --danger:#c2594a; --line:rgba(233,237,242,0.1);
  }
  *{box-sizing:border-box; margin:0; padding:0;}
  html,body{ background:var(--charcoal); color:var(--bone); font-family:'JetBrains Mono', monospace; min-height:100vh; }
  body{ display:flex; flex-direction:column; align-items:center; padding:5vh 5vw 6vh;
        background-image: radial-gradient(circle at 90% 0%, rgba(63,184,175,0.08), transparent 45%); }
  .wrap{ width:100%; max-width:920px; }
  .eyebrow{ font-size:11px; letter-spacing:0.22em; text-transform:uppercase; color:var(--teal);
            display:flex; align-items:center; gap:10px; margin-bottom:16px; }
  .eyebrow::before{ content:""; width:18px; height:1px; background:var(--teal); display:inline-block; }
  h1{ font-family:'Fraunces', serif; font-weight:700; font-size:clamp(1.8rem, 4.4vw, 2.6rem); margin-bottom:12px; }
  h1 em{ font-style:italic; font-weight:400; color:var(--teal); }
  .sub{ color:var(--bone-dim); font-size:13px; line-height:1.6; max-width:64ch; margin-bottom:14px; }
  .ethics-note{
    border:1px solid rgba(217,164,65,0.35); background:rgba(217,164,65,0.08); color:#e6c178;
    font-size:12px; line-height:1.6; padding:12px 14px; border-radius:4px; margin-bottom:30px;
  }
  .controls{ display:flex; align-items:center; gap:12px; margin-bottom:26px; flex-wrap:wrap; }
  button{
    background:none; border:1px solid var(--line); color:var(--bone-dim);
    font-family:'JetBrains Mono', monospace; font-size:11px; letter-spacing:0.06em; text-transform:uppercase;
    padding:10px 16px; border-radius:3px; cursor:pointer; transition:all .2s ease;
  }
  button#startBtn:hover{ border-color:var(--teal); color:var(--teal); }
  button#stopBtn:hover{ border-color:var(--danger); color:var(--danger); }
  .status-pill{
    font-size:11px; letter-spacing:0.05em; padding:7px 12px; border-radius:20px;
    border:1px solid var(--line); color:var(--bone-dim);
  }
  .status-pill.live{ color:var(--teal); border-color:var(--teal); }
  .status-pill.live::before{ content:"● "; }
  .meta{ font-size:11px; color:var(--bone-dim); margin-left:auto; }

  table{ width:100%; border-collapse:collapse; font-size:12px; }
  thead th{
    text-align:left; font-size:10px; letter-spacing:0.08em; text-transform:uppercase;
    color:var(--bone-dim); border-bottom:1px solid var(--line); padding:8px 10px; font-weight:500;
  }
  tbody td{ padding:8px 10px; border-bottom:1px solid var(--line); color:var(--bone); vertical-align:top; }
  tbody tr:hover{ background:var(--charcoal-2); }
  .proto{ font-weight:700; letter-spacing:0.04em; }
  .proto-TCP{ color:var(--teal); }
  .proto-UDP{ color:var(--amber); }
  .proto-ICMP{ color:#9d7fd9; }
  .proto-OTHER{ color:var(--bone-dim); }
  .payload{ color:var(--bone-dim); font-size:11px; }
  .table-wrap{ border:1px solid var(--line); border-radius:4px; overflow:auto; max-height:480px; background:var(--charcoal-2); }
  .empty-state{ padding:40px; text-align:center; color:var(--bone-dim); font-size:12px; }

  footer{ margin-top:40px; font-size:10px; letter-spacing:0.1em; text-transform:uppercase; color:var(--bone-dim); opacity:0.5; }
</style>
</head>
<body>
<div class="wrap">
  <div class="eyebrow">Task 05 Network Analyzer</div>
  <h1>Packet Pulse — <em>watch your own traffic</em></h1>
  <p class="sub">Captures packets moving through your machine's network interface and breaks each one down: source, destination, protocol, length, and a short payload preview.</p>
  <div class="ethics-note">
    Ethical use only: run this on networks and devices you own or have explicit permission to monitor.
    Requires elevated privileges to capture (run with sudo / as Administrator).
  </div>

  <div class="controls">
    <button id="startBtn">Start capture</button>
    <button id="stopBtn">Stop capture</button>
    <span class="status-pill" id="statusPill">Idle</span>
    <span class="meta" id="metaInfo">0 packets</span>
  </div>

  <div class="table-wrap">
    <table>
      <thead>
        <tr><th>Time</th><th>Source</th><th>Destination</th><th>Proto</th><th>Ports</th><th>Len</th><th>Payload</th></tr>
      </thead>
      <tbody id="packetBody">
        <tr><td colspan="7" class="empty-state">No packets captured yet. Press Start capture.</td></tr>
      </tbody>
    </table>
  </div>

  <footer>Packet network analyzer</footer>
</div>

<script>
  const startBtn = document.getElementById('startBtn');
  const stopBtn = document.getElementById('stopBtn');
  const statusPill = document.getElementById('statusPill');
  const metaInfo = document.getElementById('metaInfo');
  const packetBody = document.getElementById('packetBody');
  let pollTimer = null;

  function escapeHtml(s){
    return (s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  }

  function renderPackets(data){
    statusPill.textContent = data.running ? 'Live' : 'Idle';
    statusPill.classList.toggle('live', data.running);
    metaInfo.textContent = `${data.count} packets`;

    if(!data.packets || data.packets.length === 0){
      packetBody.innerHTML = '<tr><td colspan="7" class="empty-state">No packets captured yet. Press Start capture.</td></tr>';
      return;
    }
    packetBody.innerHTML = data.packets.map(p => {
      const ports = (p.sport && p.dport) ? `${p.sport} → ${p.dport}` : '—';
      return `<tr>
        <td>${escapeHtml(p.time)}</td>
        <td>${escapeHtml(p.src)}</td>
        <td>${escapeHtml(p.dst)}</td>
        <td class="proto proto-${p.proto}">${p.proto}</td>
        <td>${ports}</td>
        <td>${p.length}</td>
        <td class="payload">${escapeHtml(p.payload)}</td>
      </tr>`;
    }).join('');
  }

  async function poll(){
    try{
      const res = await fetch('/api/packets');
      const data = await res.json();
      renderPackets(data);
    }catch(err){
      statusPill.textContent = 'Server offline';
      statusPill.classList.remove('live');
    }
  }

  startBtn.addEventListener('click', async () => {
    await fetch('/api/start', { method:'POST' });
    if(!pollTimer) pollTimer = setInterval(poll, 1000);
    poll();
  });

  stopBtn.addEventListener('click', async () => {
    await fetch('/api/stop', { method:'POST' });
    poll();
  });

  pollTimer = setInterval(poll, 1000);
  poll();
</script>
</body>
</html>
"""

if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)