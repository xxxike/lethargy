import os
import threading
import queue
import time
import json

from flask import Flask, Response, request, send_from_directory, jsonify

from scapy.all import sniff, conf
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP


app = Flask(__name__, static_folder="public", static_url_path="/public")


def format_packet(pkt):
    ts = time.strftime("%H:%M:%S", time.localtime(float(pkt.time)))
    info = {
        "time": ts,
        "src": "?",
        "dst": "?",
        "src_mac": "?",
        "dst_mac": "?",
        "proto": "PKT",
        "length": len(pkt),
    }
    if pkt.haslayer(Ether):
        info["src_mac"] = pkt[Ether].src
        info["dst_mac"] = pkt[Ether].dst
    if pkt.haslayer(IP):
        info["src"] = pkt[IP].src
        info["dst"] = pkt[IP].dst
        if pkt.haslayer(TCP):
            info["proto"] = f"TCP {pkt[TCP].sport}->{pkt[TCP].dport}"
        elif pkt.haslayer(UDP):
            info["proto"] = f"UDP {pkt[UDP].sport}->{pkt[UDP].dport}"
        elif pkt.haslayer(ICMP):
            info["proto"] = "ICMP"
        else:
            info["proto"] = "IP"
    elif pkt.haslayer(ARP):
        info["src"] = pkt[ARP].psrc
        info["dst"] = pkt[ARP].pdst
        info["proto"] = "ARP"
    elif pkt.haslayer(Ether):
        info["src"] = info["src_mac"]
        info["dst"] = info["dst_mac"]
        info["proto"] = str(pkt[Ether].type)
    return info


sniff_thread = None
sniff_stop = threading.Event()
event_queue = queue.Queue(maxsize=1000)


def _sniff_worker(iface, bpf_filter):
    conf.verb = 0
    def _push(pkt):
        try:
            event_queue.put_nowait(format_packet(pkt))
        except queue.Full:
            pass
    sniff(
        iface=iface,
        filter=bpf_filter,
        prn=_push,
        stop_filter=lambda _: sniff_stop.is_set(),
        store=False,
    )


@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.route("/events")
def sse_stream():
    def _gen():
        while not sniff_stop.is_set():
            try:
                item = event_queue.get(timeout=0.5)
            except queue.Empty:
                yield "event: ping\n" "data: {}\n\n"
                continue
            yield f"data: {json.dumps(item)}\n\n"
    return Response(_gen(), mimetype="text/event-stream")


@app.route("/start", methods=["POST"])
def start_sniff():
    global sniff_thread
    if sniff_thread and sniff_thread.is_alive():
        return jsonify({"status": "already_running"})

    sniff_stop.clear()
    while not event_queue.empty():
        try:
            event_queue.get_nowait()
        except Exception:
            break

    payload = request.get_json(silent=True) or {}
    iface = payload.get("iface")
    bpf = payload.get("filter")

    sniff_thread = threading.Thread(target=_sniff_worker, args=(iface, bpf), daemon=True)
    sniff_thread.start()
    return jsonify({"status": "started"})


@app.route("/stop", methods=["POST"])
def stop_sniff():
    sniff_stop.set()
    return jsonify({"status": "stopping"})


def main():
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="127.0.0.1", port=port, debug=False, threaded=True)


if __name__ == "__main__":
    main()


