#!/usr/bin/env python3
"""Advanced Privacy Defense: conservative Linux proxy/VPN helper."""
from __future__ import annotations
import argparse, ipaddress, json, os, re, shutil, socket, subprocess, sys, tempfile, threading
from pathlib import Path
from urllib.parse import urlsplit

APP="Advanced Privacy Defense"
VERSION="1.2.1"
DEFAULT_PROXY="socks5h://127.0.0.1:9050"
WG_DIR=Path("/etc/wireguard")
def config_path():
    return Path(os.environ.get("XDG_CONFIG_HOME", str(Path.home()/".config")))/"advanced-privacy-defense"/"config.json"
def defaults():
    return {"proxy":DEFAULT_PROXY,"mode":"balanced","scope":"both"}
def validate_proxy(value):
    if not isinstance(value,str) or not value or len(value)>2048: raise ValueError("Proxy URL kosong atau terlalu panjang.")
    try: p=urlsplit(value); port=p.port
    except ValueError as e: raise ValueError("Format URL/port proxy tidak valid.") from e
    if p.scheme not in {"socks5","socks5h","http","https"}: raise ValueError("Skema proxy tidak didukung.")
    if not p.hostname or port is None or not 1<=port<=65535: raise ValueError("Proxy wajib memiliki hostname dan port valid.")
    if p.username is not None or p.password is not None: raise ValueError("Kredensial URL tidak didukung; jangan simpan password plaintext.")
    if p.path not in ("","/") or p.query or p.fragment: raise ValueError("URL proxy tidak boleh memiliki path/query/fragment.")
    return p
def save_config(data,path=None):
    path=path or config_path()
    validate_proxy(data.get("proxy"))
    if data.get("mode","balanced")!="balanced" or data.get("scope","both")!="both": raise ValueError("Build ini hanya mendukung balanced/both.")
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o700); os.chmod(path.parent,0o700)
    payload=json.dumps({"proxy":data["proxy"],"mode":"balanced","scope":"both"},indent=2)+"\n"
    fd,tmp=tempfile.mkstemp(prefix=".config-",dir=str(path.parent))
    try:
        os.fchmod(fd,0o600)
        with os.fdopen(fd,"w",encoding="utf-8") as f: f.write(payload); f.flush(); os.fsync(f.fileno())
        os.replace(tmp,path); os.chmod(path,0o600)
    finally:
        try: os.unlink(tmp)
        except FileNotFoundError: pass
def load_config(path=None):
    path=path or config_path()
    flags=os.O_RDONLY | getattr(os,"O_NOFOLLOW",0) | getattr(os,"O_CLOEXEC",0) | getattr(os,"O_NONBLOCK",0)
    try:
        fd=os.open(path,flags)
        try:
            info=os.fstat(fd)
            if not __import__("stat").S_ISREG(info.st_mode):
                raise ValueError("Konfigurasi harus berupa file biasa; symlink/special file ditolak.")
            if info.st_size>16384: raise ValueError("File konfigurasi terlalu besar.")
            chunks=[]; total=0
            while True:
                chunk=os.read(fd,min(4096,16385-total))
                if not chunk: break
                chunks.append(chunk); total+=len(chunk)
                if total>16384: raise ValueError("File konfigurasi terlalu besar.")
            raw=b"".join(chunks)
        finally:
            os.close(fd)
        data=json.loads(raw.decode("utf-8"))
        if not isinstance(data,dict): raise ValueError("Format konfigurasi tidak valid.")
        result=defaults(); result.update(data); validate_proxy(result["proxy"])
        if result["mode"]!="balanced" or result["scope"]!="both": raise ValueError("Mode/scope tidak didukung.")
        return result
    except FileNotFoundError:
        result=defaults(); save_config(result,path); return result
    except (UnicodeError,json.JSONDecodeError) as e: raise ValueError(f"Konfigurasi rusak: {e}") from e
def run_cmd(args,timeout=15):
    try: return subprocess.run(args,text=True,capture_output=True,timeout=timeout,check=False)
    except (OSError,subprocess.TimeoutExpired): return None
def endpoint_reachable(proxy,timeout=3):
    p=validate_proxy(proxy)
    try: addresses=socket.getaddrinfo(p.hostname,p.port,type=socket.SOCK_STREAM)
    except OSError: return False
    for family,kind,proto,_,addr in addresses:
        s=socket.socket(family,kind,proto); s.settimeout(timeout)
        try: s.connect(addr); return True
        except OSError: pass
        finally: s.close()
    return False
def proxy_request(proxy,timeout=20):
    validate_proxy(proxy); curl=shutil.which("curl")
    if not curl: return False,"curl tidak ditemukan."
    r=run_cmd([curl,"--silent","--show-error","--fail","--connect-timeout","8","--max-time",str(timeout),"--proxy",proxy,"--noproxy","","--proto","=https","--tlsv1.2","https://api.ipify.org"],timeout+3)
    if r is None: return False,"curl gagal/timeout."
    if r.returncode: return False,r.stderr.strip() or "Request HTTPS melalui proxy gagal."
    value=r.stdout.strip()
    try: ipaddress.ip_address(value)
    except ValueError: return False,"Endpoint tes tidak mengembalikan IP valid."
    return True,value
def tor_check(proxy=None,timeout=20):
    """Verify the configured SOCKS proxy against Tor Project's own check API."""
    proxy=proxy or load_config()["proxy"]
    validate_proxy(proxy)
    curl=shutil.which("curl")
    if not curl: return False,"curl tidak ditemukan."
    r=run_cmd([curl,"--silent","--show-error","--fail","--connect-timeout","8","--max-time",str(timeout),"--proxy",proxy,"--noproxy","","--proto","=https","--tlsv1.2","https://check.torproject.org/api/ip"],timeout+3)
    if r is None: return False,"Tor check gagal/timeout."
    if r.returncode: return False,r.stderr.strip() or "Tor check endpoint tidak dapat dijangkau."
    try:
        data=json.loads(r.stdout)
        if not isinstance(data,dict) or not isinstance(data.get("IsTor"),bool):
            raise ValueError("Respons API tidak memiliki IsTor boolean.")
        exit_ip=str(ipaddress.ip_address(data.get("IP","")))
    except (ValueError,TypeError,json.JSONDecodeError) as e:
        return False,f"Respons Tor check tidak valid: {e}"
    if data["IsTor"] is not True:
        return False,f"Proxy merespons tetapi tidak terverifikasi sebagai exit Tor (IP: {exit_ip})."
    return True,f"Tor terverifikasi oleh check.torproject.org; exit IP: {exit_ip}"

def direct_ip_request():
    curl=shutil.which("curl")
    if not curl: return None
    r=run_cmd([curl,"--silent","--show-error","--fail","--connect-timeout","5","--max-time","10","--noproxy","*","--proto","=https","https://api.ipify.org"],13)
    if not r or r.returncode: return None
    try: return str(ipaddress.ip_address(r.stdout.strip()))
    except ValueError: return None
def launch(command,proxy):
    if not command: raise ValueError("Perintah aplikasi tidak diberikan.")
    validate_proxy(proxy); ok,detail=proxy_request(proxy)
    if not ok:
        print("[BLOCKED] Proxy check gagal:",detail,file=sys.stderr); print("Aplikasi tidak dijalankan.",file=sys.stderr); return 2
    env=os.environ.copy()
    env.update({"HTTP_PROXY":proxy,"HTTPS_PROXY":proxy,"ALL_PROXY":proxy,"http_proxy":proxy,"https_proxy":proxy,"all_proxy":proxy,"NO_PROXY":"localhost,127.0.0.1,::1","no_proxy":"localhost,127.0.0.1,::1"})
    print("[PASS] HTTPS test melalui proxy; egress:",detail)
    print("[WARN] Aplikasi tujuan masih dapat mengabaikan proxy environment.")
    try: return subprocess.run(command,env=env,check=False).returncode
    except OSError as e: print("Gagal menjalankan aplikasi:",e,file=sys.stderr); return 127
def redact_text(content):
    """Remove common credentials and local identity markers from text before sharing."""
    patterns = [
        (r"(?i)(authorization\s*:\s*bearer\s+)[^\s,;]+", r"\1[REDACTED]"),
        (r"(?i)(authorization\s*:\s*basic\s+)[^\s,;]+", r"\1[REDACTED]"),
        (r"(?i)(\b(?:password|passwd|token|api[_-]?key|secret|client_secret)\b\s*[=:]\s*)[\"']?[^\s,;\"']+", r"\1[REDACTED]"),
        (r"(?i)(\b(?:set-cookie|cookie)\s*:\s*)[^\r\n]+", r"\1[REDACTED]"),
        (r"(?i)([?&](?:token|key|secret|password|auth)=)[^&\s]+", r"\1[REDACTED]"),
        (r"(?i)[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", "[EMAIL_REDACTED]"),
        (r"(?i)(/home/)[^/\s]+", r"\1[USER]"),
    ]
    result=content
    for pattern,replacement in patterns: result=re.sub(pattern,replacement,result)
    return result

def redact_file(source,destination=None):
    """Write a private redacted copy; open source without following symlinks."""
    import stat

    source=Path(source).expanduser()
    flags=os.O_RDONLY | getattr(os,"O_NOFOLLOW",0) | getattr(os,"O_CLOEXEC",0) | getattr(os,"O_NONBLOCK",0)
    try:
        source_fd=os.open(source,flags)
    except OSError as e:
        raise ValueError(f"File sumber tidak dapat dibuka dengan aman: {e}") from e
    try:
        info=os.fstat(source_fd)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("Sumber harus file biasa; symlink dan special file ditolak.")
        if info.st_size > 5*1024*1024:
            raise ValueError("File melebihi batas 5 MiB.")
        chunks=[]; total=0
        while True:
            chunk=os.read(source_fd,min(65536,5*1024*1024+1-total))
            if not chunk: break
            chunks.append(chunk); total+=len(chunk)
            if total>5*1024*1024:
                raise ValueError("File melebihi batas 5 MiB.")
        raw=b"".join(chunks)
    finally:
        os.close(source_fd)

    cleaned=redact_text(raw.decode("utf-8",errors="replace"))
    target=Path(destination).expanduser() if destination else source.with_name(source.name+".redacted")
    try:
        if target.exists() and os.path.samefile(source,target):
            raise ValueError("Output tidak boleh menunjuk ke file sumber.")
    except FileNotFoundError:
        pass
    target.parent.mkdir(parents=True,exist_ok=True)
    if target.exists() or target.is_symlink():
        raise ValueError("File output sudah ada; pilih nama output lain agar data tidak tertimpa.")
    fd,tmp=tempfile.mkstemp(prefix=".pps-redact-",dir=str(target.parent))
    try:
        os.fchmod(fd,0o600)
        with os.fdopen(fd,"w",encoding="utf-8") as stream:
            stream.write(cleaned); stream.flush(); os.fsync(stream.fileno())
        # Atomic no-clobber publication: link fails if target appeared concurrently.
        os.link(tmp,target)
    except FileExistsError as e:
        raise ValueError("File output sudah ada; tidak ditimpa.") from e
    finally:
        try: os.unlink(tmp)
        except FileNotFoundError: pass
    return target

def safe_profile(name):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}",name): raise ValueError("Nama profil WireGuard tidak valid.")
    return name
def profiles(directory=WG_DIR):
    try: return sorted(p.stem for p in directory.glob("*.conf") if p.is_file() and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}",p.stem))
    except OSError: return []
def wg_action(action,profile):
    if action not in {"up","down"}: raise ValueError("Aksi WireGuard tidak valid.")
    profile=safe_profile(profile)
    if profile not in profiles(): print("Profil tidak ditemukan di /etc/wireguard.",file=sys.stderr); return 2
    if not shutil.which("wg-quick") or not shutil.which("sudo"): print("wg-quick/sudo tidak ditemukan.",file=sys.stderr); return 2
    phrase=f"{action.upper()} {profile}"
    print(f"Perintah mengubah routing sistem: sudo wg-quick {action} {profile}")
    if input(f"Ketik {phrase} untuk melanjutkan: ").strip()!=phrase: print("Dibatalkan."); return 1
    r=run_cmd(["sudo","wg-quick",action,profile],90)
    if r is None: print("wg-quick gagal/timeout.",file=sys.stderr); return 2
    if r.stdout: print(r.stdout,end="")
    if r.stderr: print(r.stderr,end="",file=sys.stderr)
    return r.returncode
def output(args):
    r=run_cmd(args)
    if r is None: return "Tidak tersedia (gagal/timeout)."
    return r.stdout.strip() if r.returncode==0 and r.stdout.strip() else (r.stderr.strip() or "Tidak ada data.")
def audit():
    c=load_config()
    print(f"{APP} v{VERSION} — AUDIT")
    print("\n[DEPENDENCIES]")
    for x in ("python3","curl","tor","wg","wg-quick","nft","ip"): print(f"{x:12} {'OK' if shutil.which(x) else 'MISSING'}")
    p=validate_proxy(c["proxy"]); print("\n[PROXY]\nURL:",c["proxy"],"\nEndpoint:",f"{p.hostname}:{p.port}","\nTCP:", "REACHABLE" if endpoint_reachable(c["proxy"]) else "UNREACHABLE")
    print("\n[ROUTES]\nIPv4:",output(["ip","-4","route","show","default"]),"\nIPv6:",output(["ip","-6","route","show","default"]))
    try: dns=re.findall(r"^\s*nameserver\s+(\S+)",Path("/etc/resolv.conf").read_text(errors="replace"),re.M)
    except OSError: dns=[]
    print("\n[DNS resolver config]:",", ".join(dns) or "Unknown")
    print("\n[FIREWALL]:",output(["nft","list","ruleset"]) if shutil.which("nft") else "nftables not installed")
    print("\n[WIREGUARD]:",output(["wg","show","interfaces"]) if shutil.which("wg") else "wg missing")
    print("Profiles:",", ".join(profiles()) or "None")
    print("\nAudit ini indikator lokal, bukan penetration test/sertifikasi anonimitas. DNS, UDP, WebRTC, fingerprint, malware, dan korelasi trafik tidak diuji.")
def self_test():
    import unittest
    class Tests(unittest.TestCase):
        def test_socks5h(self): self.assertEqual(validate_proxy(DEFAULT_PROXY).port,9050)
        def test_https(self): self.assertEqual(validate_proxy("https://127.0.0.1:8443").scheme,"https")
        def test_bad_scheme(self):
            with self.assertRaises(ValueError): validate_proxy("file:///etc/passwd")
        def test_credentials(self):
            with self.assertRaises(ValueError): validate_proxy("socks5h://u:p@localhost:9050")
        def test_missing_host(self):
            with self.assertRaises(ValueError): validate_proxy("socks5h://:9050")
        def test_bad_port(self):
            with self.assertRaises(ValueError): validate_proxy("socks5h://localhost:99999")
        def test_path(self):
            with self.assertRaises(ValueError): validate_proxy("socks5h://localhost:9050/path")
        def test_profile_traversal(self):
            with self.assertRaises(ValueError): safe_profile("../bad")
        def test_config_permissions(self):
            with tempfile.TemporaryDirectory() as d:
                p=Path(d)/"cfg"/"config.json"; save_config(defaults(),p)
                self.assertEqual(load_config(p)["mode"],"balanced"); self.assertEqual(p.stat().st_mode&0o777,0o600)
        def test_reject_mode(self):
            with tempfile.TemporaryDirectory() as d:
                with self.assertRaises(ValueError): save_config({"proxy":DEFAULT_PROXY,"mode":"maximum","scope":"both"},Path(d)/"c")
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(Tests); result=unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1
def gui():
    try: import tkinter as tk; from tkinter import ttk,messagebox
    except ImportError: print("Tkinter tidak tersedia.",file=sys.stderr); return 1
    cfg=load_config(); root=tk.Tk(); root.title(APP+" — Advanced"); root.geometry("820x600"); root.minsize(660,460)
    box=ttk.Frame(root,padding=14); box.pack(fill="both",expand=True)
    ttk.Label(box,text=APP,font=("TkDefaultFont",18,"bold")).pack(anchor="w")
    ttk.Label(box,text=f"v{VERSION} | Balanced | Scope Both | Advanced UI").pack(anchor="w",pady=(0,12))
    ttk.Label(box,text="Proxy URL").pack(anchor="w"); var=tk.StringVar(value=cfg["proxy"]); ttk.Entry(box,textvariable=var).pack(fill="x",pady=5)
    text=tk.Text(box,height=20,wrap="word"); text.pack(fill="both",expand=True,pady=8)
    def log(msg): text.insert("end",str(msg)+"\n"); text.see("end")
    def bg(label,fn):
        log(label+" ...")
        def work():
            try: result=fn()
            except Exception as e: result="ERROR: "+str(e)
            root.after(0,lambda:log(result))
        threading.Thread(target=work,daemon=True).start()
    def save():
        try:
            cfg2=load_config(); cfg2["proxy"]=var.get().strip(); save_config(cfg2); log("Konfigurasi tersimpan (permission 0600).")
        except Exception as e: messagebox.showerror("Proxy tidak valid",str(e))
    def test(): bg("HTTPS proxy test",lambda: (lambda r: ("PASS: " if r[0] else "FAIL: ")+r[1])(proxy_request(var.get().strip())))
    def net():
        def work():
            try: dns=", ".join(re.findall(r"^\s*nameserver\s+(\S+)",Path("/etc/resolv.conf").read_text(errors="replace"),re.M)) or "unknown"
            except OSError: dns="unknown"
            return "IPv4: "+output(["ip","-4","route","show","default"])+"\nIPv6: "+output(["ip","-6","route","show","default"])+"\nDNS: "+dns+"\nWireGuard profiles: "+(", ".join(profiles()) or "none")
        bg("Network audit",work)
    row=ttk.Frame(box); row.pack(fill="x")
    def run_tests():
        r=run_cmd([sys.executable,str(Path(__file__).resolve()),"self-test"],30)
        if r is None: return "Unit tests gagal dijalankan/timeout."
        return (r.stdout+"\n"+r.stderr).strip()
    for label,fn in (("Save Proxy",save),("Test Proxy",test),("Network Audit",net),("Unit Tests",lambda: bg("Unit tests",run_tests))):
        ttk.Button(row,text=label,command=fn).pack(side="left",padx=3)
    log("Ready. Firewall global tidak diubah otomatis.")
    log("CLI: pps tor-check untuk verifikasi exit Tor resmi.")
    log("WireGuard: gunakan CLI pps wg up/down NAMA_PROFIL.")
    root.mainloop(); return 0
def main(argv=None):
    parser=argparse.ArgumentParser(prog="pps",description=APP); sub=parser.add_subparsers(dest="action")
    for name in ("status","audit","live-test","tor-check","self-test","gui"): sub.add_parser(name)
    p=sub.add_parser("redact-log",help="Redact common secrets and local identifiers from a text log"); p.add_argument("file"); p.add_argument("-o","--output",default=None)
    p=sub.add_parser("set-proxy"); p.add_argument("url")
    p=sub.add_parser("run"); p.add_argument("--proxy",default=None); p.add_argument("command",nargs=argparse.REMAINDER)
    p=sub.add_parser("wg"); p.add_argument("operation",choices=("up","down")); p.add_argument("profile")
    a=parser.parse_args(argv)
    try:
        if a.action=="status":
            c=load_config(); print(f"{APP} v{VERSION}\nMode: {c['mode']} | Scope: {c['scope']}\nProxy: {c['proxy']}\nConfig: {config_path()}\nWireGuard: {', '.join(profiles()) or 'none'}"); return 0
        if a.action=="audit": audit(); return 0
        if a.action=="self-test": return self_test()
        if a.action=="redact-log":
            target=redact_file(a.file,a.output); print(f"Redacted copy saved: {target} (mode 0600). Review manually before sharing."); return 0
        if a.action=="gui": return gui()
        if a.action=="set-proxy":
            c=load_config(); c["proxy"]=a.url; save_config(c); print("Proxy tersimpan."); return 0
        if a.action=="tor-check":
            ok,detail=tor_check(load_config()["proxy"]); print(("[PASS] " if ok else "[FAIL] ")+detail); return 0 if ok else 1
        if a.action=="live-test":
            ok,detail=proxy_request(load_config()["proxy"]); print(("[PASS] " if ok else "[FAIL] ")+detail)
            if ok:
                direct=direct_ip_request()
                if direct: print("Direct IP:",direct,"\nProxy IP:",detail,"\nDifferent egress:", "yes" if direct!=detail else "no")
            return 0 if ok else 1
        if a.action=="run":
            cmd=a.command[1:] if a.command[:1]==["--"] else a.command
            return launch(cmd,a.proxy or load_config()["proxy"])
        if a.action=="wg": return wg_action(a.operation,a.profile)
        parser.print_help(); return 0
    except (ValueError,OSError) as e: print("ERROR:",e,file=sys.stderr); return 2
if __name__=="__main__": raise SystemExit(main())
