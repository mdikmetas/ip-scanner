#!/usr/bin/env python3
"""
IP Tarayıcı - Windows & macOS (Python 3 + tkinter, ek paket gerekmez)

Aralık formatları:
  192.168.1.1-192.168.1.254
  192.168.1.1-254
  192.168.1.0/24
  192.168.1.1-50, 192.168.2.10-20   (virgülle birden fazla)
"""
import csv
import ipaddress
import math
import platform
import queue
import re
import socket
import subprocess
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

OS = platform.system()
MAX_HOSTS = 65536


def local_default_range():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        p = ip.split(".")
        return f"{p[0]}.{p[1]}.{p[2]}.1-{p[0]}.{p[1]}.{p[2]}.254"
    except Exception:
        return "192.168.1.1-192.168.1.254"


def parse_range(text):
    ips = []
    for part in re.split(r"[,\s;]+", text.strip()):
        if not part:
            continue
        if "/" in part:
            net = ipaddress.ip_network(part, strict=False)
            ips.extend(int(h) for h in net.hosts())
        elif "-" in part:
            left, right = part.split("-", 1)
            start = ipaddress.ip_address(left.strip())
            right = right.strip()
            if "." not in right:  # 192.168.1.1-254
                base = left.strip().rsplit(".", 1)[0]
                right = f"{base}.{right}"
            end = ipaddress.ip_address(right)
            if int(end) < int(start):
                start, end = end, start
            ips.extend(range(int(start), int(end) + 1))
        else:
            ips.append(int(ipaddress.ip_address(part)))
        if len(ips) > MAX_HOSTS:
            raise ValueError(f"Aralık çok büyük (en fazla {MAX_HOSTS} adres).")
    seen = set()
    out = []
    for i in ips:
        if i not in seen:
            seen.add(i)
            out.append(i)
    return out


def ping(ip, timeout_ms):
    if OS == "Windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
        flags = subprocess.CREATE_NO_WINDOW
    elif OS == "Darwin":
        cmd = ["ping", "-c", "1", "-W", str(timeout_ms), ip]
        flags = 0
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, math.ceil(timeout_ms / 1000))), ip]
        flags = 0
    try:
        kw = {"creationflags": flags} if flags else {}
        r = subprocess.run(cmd, capture_output=True, timeout=timeout_ms / 1000 + 3, **kw)
    except Exception:
        return False, ""
    out = r.stdout.decode("utf-8", "ignore")
    if "ttl=" not in out.lower():
        return False, ""
    m = re.search(r"[=<]\s*([\d.]+)\s*ms", out)
    ms = ("<1" if "<" in m.group(0) else m.group(1)) if m else ""
    return True, ms


def _udp_query(ip, port, packet, timeout=1.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(packet, (ip, port))
        data, _ = s.recvfrom(2048)
        return data
    except Exception:
        return b""
    finally:
        s.close()


def netbios_name(ip):
    """Windows PC'ler için NetBIOS adı (UDP 137, NBSTAT sorgusu)."""
    pkt = (b"\xab\xcd\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
           b"\x20" + b"CK" + b"A" * 30 + b"\x00" + b"\x00\x21\x00\x01")
    d = _udp_query(ip, 137, pkt)
    try:
        if len(d) < 57:
            return ""
        n = d[56]
        pos = 57
        first = ""
        for _ in range(n):
            raw = d[pos:pos + 15].decode("ascii", "ignore").strip()
            suffix = d[pos + 15]
            flags = (d[pos + 16] << 8) | d[pos + 17]
            pos += 18
            if suffix == 0x00 and not (flags & 0x8000) and raw:
                return raw
            if not first and raw and not (flags & 0x8000):
                first = raw
        return first
    except Exception:
        return ""


def _dns_read_name(d, pos):
    labels = []
    jumped = False
    end = pos
    for _ in range(64):
        ln = d[pos]
        if ln == 0:
            pos += 1
            break
        if ln & 0xC0 == 0xC0:
            ptr = ((ln & 0x3F) << 8) | d[pos + 1]
            if not jumped:
                end = pos + 2
            jumped = True
            pos = ptr
            continue
        labels.append(d[pos + 1:pos + 1 + ln].decode("utf-8", "ignore"))
        pos += 1 + ln
    if not jumped:
        end = pos
    return ".".join(labels), end


def mdns_name(ip):
    """Mac / iPhone / Linux / yazıcı gibi Bonjour cihazları için (UDP 5353)."""
    qname = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    q = b"".join(bytes([len(p)]) + p.encode() for p in qname.split(".")) + b"\x00"
    pkt = b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" + q + b"\x00\x0c\x00\x01"
    d = _udp_query(ip, 5353, pkt)
    try:
        if len(d) < 12:
            return ""
        an = (d[6] << 8) | d[7]
        if an == 0:
            return ""
        pos = 12
        _, pos = _dns_read_name(d, pos)  # soru
        pos += 4
        for _ in range(an):
            _, pos = _dns_read_name(d, pos)
            rtype = (d[pos] << 8) | d[pos + 1]
            rdlen = (d[pos + 8] << 8) | d[pos + 9]
            pos += 10
            if rtype == 12:
                name, _ = _dns_read_name(d, pos)
                return name
            pos += rdlen
    except Exception:
        pass
    return ""


def resolve_host(ip):
    """Sırayla: ters DNS -> NetBIOS -> mDNS. İlk bulunan ad döner."""
    try:
        name = socket.gethostbyaddr(ip)[0]
        if name and name != ip:
            return name
    except Exception:
        pass
    return netbios_name(ip) or mdns_name(ip) or ""


# Derin tarama: yaygın servis portları (cihazın ne olduğunu da gösterir)
PORT_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 53: "DNS", 80: "HTTP", 135: "RPC",
    139: "NetBIOS", 443: "HTTPS", 445: "SMB", 548: "AFP", 554: "RTSP",
    3389: "RDP", 5900: "VNC", 8000: "HTTP-alt", 8080: "HTTP-alt",
    8443: "HTTPS-alt", 9100: "Yazıcı", 62078: "iPhone",
}


def tcp_probe(ip, timeout=0.4):
    """Yaygın portlara bağlanmayı dener.
    Bağlantı kabul edildi veya reddedildi (RST) = cihaz ayakta demektir.
    Döner: (ayakta_mi, açık_port_listesi)"""
    alive = False
    open_ports = []
    for port in PORT_NAMES:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((ip, port))
            alive = True
            open_ports.append(port)
        except ConnectionRefusedError:
            alive = True
        except OSError:
            pass
        finally:
            s.close()
    return alive, open_ports


def ports_text(ports):
    return ", ".join(PORT_NAMES.get(p, str(p)) for p in ports)


def read_arp():
    table = {}
    try:
        kw = {"creationflags": subprocess.CREATE_NO_WINDOW} if OS == "Windows" else {}
        out = subprocess.run(["arp", "-a"], capture_output=True, timeout=10, **kw)
        text = out.stdout.decode("utf-8", "ignore")
    except Exception:
        return table
    pat = re.compile(r"(\d+\.\d+\.\d+\.\d+)\W+.*?([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})")
    for line in text.splitlines():
        m = pat.search(line)
        if not m:
            continue
        octets = re.split(r"[:-]", m.group(2))
        mac = ":".join(o.zfill(2) for o in octets).upper()
        if mac in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"):
            continue
        table[m.group(1)] = mac
    return table


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("IP Tarayıcı")
        self.geometry("980x580")
        self.minsize(640, 420)

        self.q = queue.Queue()
        self.stop_event = threading.Event()
        self.scanning = False
        self.results = {}  # ip -> dict
        self.total = 0
        self.done_count = 0
        self.start_time = 0

        self.range_var = tk.StringVar(value=local_default_range())
        self.threads_var = tk.IntVar(value=100)
        self.timeout_var = tk.IntVar(value=800)
        self.only_alive = tk.BooleanVar(value=True)
        self.resolve_var = tk.BooleanVar(value=True)
        self.deep_var = tk.BooleanVar(value=True)
        self.status_var = tk.StringVar(value="Hazır")

        self._build()
        self.after(100, self._poll)

    def _build(self):
        top = ttk.Frame(self, padding=10)
        top.pack(fill="x")
        ttk.Label(top, text="IP aralığı:").grid(row=0, column=0, sticky="w")
        e = ttk.Entry(top, textvariable=self.range_var)
        e.grid(row=0, column=1, sticky="ew", padx=6)
        e.bind("<Return>", lambda _e: self.start())
        self.btn = ttk.Button(top, text="Tara", command=self.start, width=10)
        self.btn.grid(row=0, column=2)
        top.columnconfigure(1, weight=1)

        opt = ttk.Frame(self, padding=(10, 0))
        opt.pack(fill="x")
        ttk.Label(opt, text="Thread:").pack(side="left")
        ttk.Spinbox(opt, from_=1, to=500, width=5, textvariable=self.threads_var).pack(side="left", padx=(4, 12))
        ttk.Label(opt, text="Zaman aşımı (ms):").pack(side="left")
        ttk.Spinbox(opt, from_=100, to=5000, increment=100, width=6, textvariable=self.timeout_var).pack(side="left", padx=(4, 12))
        ttk.Checkbutton(opt, text="Cihaz adını bul", variable=self.resolve_var).pack(side="left", padx=(0, 12))
        ttk.Checkbutton(opt, text="Derin tarama (ping'e cevap vermeyenleri de bul)", variable=self.deep_var).pack(side="left", padx=(0, 12))
        ttk.Checkbutton(opt, text="Sadece açık olanlar", variable=self.only_alive, command=self._refill).pack(side="left")

        mid = ttk.Frame(self, padding=10)
        mid.pack(fill="both", expand=True)
        cols = ("ip", "durum", "ms", "host", "mac", "ports")
        self.tree = ttk.Treeview(mid, columns=cols, show="headings", selectmode="extended")
        heads = {"ip": ("IP Adresi", 130), "durum": ("Durum", 70), "ms": ("Ping (ms)", 80),
                 "host": ("Cihaz Adı", 220), "mac": ("MAC", 140),
                 "ports": ("Açık Servisler", 220)}
        for c in cols:
            self.tree.heading(c, text=heads[c][0])
            self.tree.column(c, width=heads[c][1], anchor="w")
        sb = ttk.Scrollbar(mid, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.tree.tag_configure("up", foreground="#0a7d2c")
        self.tree.tag_configure("down", foreground="#999999")

        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label="IP'yi kopyala", command=self._copy_ips)
        self.tree.bind("<Button-3>", lambda ev: menu.tk_popup(ev.x_root, ev.y_root))
        self.tree.bind("<Button-2>", lambda ev: menu.tk_popup(ev.x_root, ev.y_root))
        self.bind("<Control-c>", lambda _e: self._copy_ips())
        self.bind("<Command-c>", lambda _e: self._copy_ips())

        bottom = ttk.Frame(self, padding=(10, 0, 10, 10))
        bottom.pack(fill="x")
        self.bar = ttk.Progressbar(bottom, mode="determinate")
        self.bar.pack(fill="x")
        row = ttk.Frame(bottom)
        row.pack(fill="x", pady=(6, 0))
        ttk.Label(row, textvariable=self.status_var).pack(side="left")
        ttk.Button(row, text="CSV'ye aktar", command=self.export_csv).pack(side="right")
        ttk.Button(row, text="Temizle", command=self.clear).pack(side="right", padx=6)

    # ---- tarama ----
    def start(self):
        if self.scanning:
            self.stop_event.set()
            self.status_var.set("Durduruluyor...")
            return
        try:
            ips = parse_range(self.range_var.get())
        except Exception as ex:
            messagebox.showerror("Hata", f"Geçersiz aralık:\n{ex}")
            return
        if not ips:
            messagebox.showerror("Hata", "Taranacak adres yok.")
            return
        try:
            nthreads = max(1, min(500, int(self.threads_var.get())))
            timeout = max(100, int(self.timeout_var.get()))
        except Exception:
            messagebox.showerror("Hata", "Thread / zaman aşımı sayısal olmalı.")
            return

        self.clear()
        self.stop_event.clear()
        self.scanning = True
        self.btn.config(text="Durdur")
        self.total = len(ips)
        self.done_count = 0
        self.bar.config(maximum=self.total, value=0)
        self.start_time = time.time()
        self.status_var.set(f"Taranıyor... 0/{self.total}")

        work = queue.Queue()
        for i in ips:
            work.put(str(ipaddress.ip_address(i)))
        resolve = self.resolve_var.get()
        deep = self.deep_var.get()
        dead_ips = []  # ping/port'a cevap vermeyenler (sonda ARP'a bakılacak)

        def worker():
            while not self.stop_event.is_set():
                try:
                    ip = work.get_nowait()
                except queue.Empty:
                    return
                alive, ms = ping(ip, timeout)
                ports = []
                host = ""
                if deep:
                    a2, ports = tcp_probe(ip)
                    if not alive and a2:
                        alive, ms = True, "-"
                    if not alive:
                        nb = netbios_name(ip)  # NetBIOS cevabı da "ayakta" demek
                        if nb:
                            alive, ms, host = True, "-", nb
                if alive and resolve and not host:
                    host = resolve_host(ip)
                if not alive:
                    dead_ips.append(ip)
                self.q.put(("res", ip, alive, ms, host, ports_text(ports)))

        threads = [threading.Thread(target=worker, daemon=True) for _ in range(min(nthreads, self.total))]
        for t in threads:
            t.start()

        def coordinator():
            for t in threads:
                t.join()
            arp = read_arp()
            if deep and not self.stop_event.is_set():
                # Ping ve portlara hiç cevap vermese bile ARP tablosunda MAC'i
                # olan cihaz aynı ağda ayaktadır (iPhone, sessiz Windows PC vb.)
                for ip in dead_ips:
                    if ip in arp:
                        host = resolve_host(ip) if resolve else ""
                        self.q.put(("upd", ip, host))
            self.q.put(("done", arp))

        threading.Thread(target=coordinator, daemon=True).start()

    def _poll(self):
        try:
            for _ in range(500):
                msg = self.q.get_nowait()
                if msg[0] == "res":
                    _, ip, alive, ms, host, ports = msg
                    self.results[ip] = {"ip": ip, "alive": alive, "ms": ms, "host": host,
                                        "mac": "", "ports": ports}
                    self.done_count += 1
                    if alive or not self.only_alive.get():
                        self._insert(self.results[ip])
                elif msg[0] == "upd":
                    _, ip, host = msg
                    if ip in self.results:
                        self.results[ip].update(alive=True, ms="-", host=host)
                elif msg[0] == "done":
                    self._finish(msg[1])
        except queue.Empty:
            pass
        if self.scanning:
            self.bar.config(value=self.done_count)
            alive = sum(1 for r in self.results.values() if r["alive"])
            self.status_var.set(f"Taranıyor... {self.done_count}/{self.total}  |  Açık: {alive}")
        self.after(100, self._poll)

    def _finish(self, arp=None):
        if arp is None:
            arp = read_arp()
        for ip, r in self.results.items():
            if ip in arp:
                r["mac"] = arp[ip]
        stopped = self.stop_event.is_set()
        self.scanning = False
        self.btn.config(text="Tara")
        self.bar.config(value=self.done_count)
        self._refill()
        alive = sum(1 for r in self.results.values() if r["alive"])
        el = time.time() - self.start_time
        self.status_var.set(
            f"{'Durduruldu' if stopped else 'Bitti'}: {self.done_count}/{self.total} tarandı, "
            f"{alive} açık  ({el:.1f} sn)"
        )

    # ---- liste ----
    def _insert(self, r):
        self.tree.insert("", "end", values=(
            r["ip"], "Açık" if r["alive"] else "Kapalı", r["ms"], r["host"], r["mac"],
            r.get("ports", "")
        ), tags=("up" if r["alive"] else "down",))

    def _refill(self):
        self.tree.delete(*self.tree.get_children())
        key = lambda r: tuple(int(x) for x in r["ip"].split("."))
        for r in sorted(self.results.values(), key=key):
            if r["alive"] or not self.only_alive.get():
                self._insert(r)

    def clear(self):
        if self.scanning:
            return
        self.results.clear()
        self.tree.delete(*self.tree.get_children())
        self.bar.config(value=0)
        self.status_var.set("Hazır")

    def _copy_ips(self):
        sel = self.tree.selection()
        if not sel:
            return
        text = "\n".join(self.tree.item(i, "values")[0] for i in sel)
        self.clipboard_clear()
        self.clipboard_append(text)

    def export_csv(self):
        if not self.results:
            messagebox.showinfo("Bilgi", "Aktarılacak sonuç yok.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")],
                                            initialfile="ip_tarama.csv")
        if not path:
            return
        key = lambda r: tuple(int(x) for x in r["ip"].split("."))
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            w.writerow(["IP", "Durum", "Ping (ms)", "Cihaz Adı", "MAC", "Açık Servisler"])
            for r in sorted(self.results.values(), key=key):
                if r["alive"] or not self.only_alive.get():
                    w.writerow([r["ip"], "Açık" if r["alive"] else "Kapalı", r["ms"], r["host"], r["mac"], r.get("ports", "")])
        self.status_var.set(f"Kaydedildi: {path}")


if __name__ == "__main__":
    App().mainloop()
