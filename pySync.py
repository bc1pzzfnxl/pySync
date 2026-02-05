import os
import time
import json
import sys
import hashlib
import threading
import requests
import uvicorn
from concurrent.futures import ThreadPoolExecutor
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from fastapi import FastAPI, HTTPException, BackgroundTasks, Header, Depends
from fastapi.responses import FileResponse, JSONResponse

# ================= CONFIGURATION LOADER =================

CONFIG_FILE = "config.json"
STATE_FILE = "pysync.db"
PORT = 7777
# Files to strictly ignore
IGNORE_FILES = ["workspace.json", ".DS_Store", "desktop.ini", STATE_FILE, CONFIG_FILE, ".git"]

try:
    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        config = json.load(f)
        
    SYNC_DIR = config["sync_dir"]
    PEERS = config["peers"]
    AUTH_TOKEN = config.get("auth_token")

    if not os.path.exists(SYNC_DIR):
        print(f"ERROR: The directory {SYNC_DIR} does not exist.")
        sys.exit(1)
    
    if not AUTH_TOKEN:
        print(f"ERROR: 'auth_token' is missing in {CONFIG_FILE}. Please add it.")
        sys.exit(1)
        
    print(f"Configuration loaded. Syncing: {SYNC_DIR}")
    
except FileNotFoundError:
    print(f"ERROR: {CONFIG_FILE} not found. Please create it.")
    sys.exit(1)
except json.JSONDecodeError:
    print(f"ERROR: {CONFIG_FILE} is not a valid JSON file.")
    sys.exit(1)

# ================= STATE MANAGEMENT =================

# State structure: {"files": {path: {mtime, hash}}, "tombstones": {path: timestamp}}
LOCAL_STATE = {"files": {}, "tombstones": {}}
STATE_LOCK = threading.Lock()
# Event triggers sync immediately when set
SYNC_EVENT = threading.Event()
LAST_NOTIFY = 0

def load_state():
    global LOCAL_STATE
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                content = f.read().strip()
                if not content:
                    LOCAL_STATE = {"files": {}, "tombstones": {}}
                    return
                LOCAL_STATE = json.loads(content)
                
                if "files" not in LOCAL_STATE: LOCAL_STATE["files"] = {}
                if "tombstones" not in LOCAL_STATE: LOCAL_STATE["tombstones"] = {}
                
        except (json.JSONDecodeError, Exception) as e:
            print(f"[!] Warning: Could not load state ({e}). Starting with fresh state.")
            LOCAL_STATE = {"files": {}, "tombstones": {}}

def save_state():
    with STATE_LOCK:
        try:
            with open(STATE_FILE, "w", encoding="utf-8") as f:
                json.dump(LOCAL_STATE, f)
        except Exception as e:
            print(f"Error saving state: {e}")

# Load state on startup
load_state()

# ================= WATCHDOG HANDLER =================

class ChangeHandler(FileSystemEventHandler):
    def on_any_event(self, event):
        if event.is_directory: return
        
        filename = os.path.basename(event.src_path)
        if filename in IGNORE_FILES or filename.endswith(".tmp") or filename.endswith(".bak"): return
        
        print(f"[Watchdog] Change detected: {event.src_path}")
        SYNC_EVENT.set()
        
        # Debounce network notification (Limit to 1 per 2 seconds)
        global LAST_NOTIFY
        with STATE_LOCK:
            now = time.time()
            if now - LAST_NOTIFY < 2:
                return
            LAST_NOTIFY = now
        
        threading.Thread(target=notify_peers, daemon=True).start()

def notify_peers():
    """Tells all peers that I have updates."""
    for peer in PEERS:
        try:
            url = peer if peer.startswith("http") else f"http://{peer}"
            requests.post(
                f"{url}/notify", 
                timeout=1,
                headers={"X-Auth-Token": AUTH_TOKEN}
            )
        except:
            pass

# ================= SERVER & AUTH =================

MY_ID = os.environ.get("COMPUTERNAME", os.environ.get("HOSTNAME", "PC_UNKNOWN"))
app = FastAPI()

async def verify_token(x_auth_token: str = Header(...)):
    if x_auth_token != AUTH_TOKEN:
        raise HTTPException(status_code=403, detail="Invalid Auth Token")

def calculate_hash(filepath):
    """Calculates MD5 checksum to verify exact content."""
    hash_md5 = hashlib.md5()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except (FileNotFoundError, PermissionError):
        return None

def scan_local_files():
    """Scans the directory, updates LOCAL_STATE, and detects deletions."""
    current_files = {}
    
    # 1. Scan current files on disk
    for root, _, files in os.walk(SYNC_DIR):
        if ".git" in root: continue 
        
        for file in files:
            if file in IGNORE_FILES or file.endswith(".tmp") or file.endswith(".bak"): continue
            
            path = os.path.join(root, file)
            rel_path = os.path.relpath(path, SYNC_DIR).replace("\\", "/")
            
            try:
                stat = os.stat(path)
                cached = LOCAL_STATE["files"].get(rel_path)
                
                if cached and cached["mtime"] == stat.st_mtime:
                    file_hash = cached["hash"]
                else:
                    file_hash = calculate_hash(path)
                
                if file_hash:
                    current_files[rel_path] = {
                        "mtime": stat.st_mtime,
                        "hash": file_hash
                    }
            except OSError:
                pass

    with STATE_LOCK:
        # 2. Detect Deletions
        for old_path in list(LOCAL_STATE["files"].keys()):
            if old_path not in current_files:
                print(f"[-] Detected local deletion: {old_path}")
                LOCAL_STATE["tombstones"][old_path] = time.time()
        
        # 3. Update State
        LOCAL_STATE["files"] = current_files
        
        for new_path in current_files:
            if new_path in LOCAL_STATE["tombstones"]:
                del LOCAL_STATE["tombstones"][new_path]

        # Cleanup old tombstones (> 30 days)
        now = time.time()
        expired = [p for p, t in LOCAL_STATE["tombstones"].items() if now - t > 2592000]
        for p in expired:
            del LOCAL_STATE["tombstones"][p]

    save_state()
    return LOCAL_STATE

# --- ENDPOINTS ---

@app.get("/index", dependencies=[Depends(verify_token)])
def get_index():
    return scan_local_files()

@app.get("/download/{file_path:path}", dependencies=[Depends(verify_token)])
def download_file(file_path: str):
    if ".." in file_path: raise HTTPException(403)
    full_path = os.path.join(SYNC_DIR, file_path)
    if os.path.exists(full_path):
        return FileResponse(full_path)
    raise HTTPException(404)

@app.post("/notify", dependencies=[Depends(verify_token)])
def receive_notification(background_tasks: BackgroundTasks):
    """Endpoint called by peers when they have changes."""
    print("[!] Notification received from peer: Triggering Sync.")
    SYNC_EVENT.set()
    return {"status": "ok"}

# --- CLIENT SIDE ---

def sync_with_peer(peer_url):
    try:
        if not peer_url.startswith("http"):
            peer_url = f"http://{peer_url}"

        resp = requests.get(
            f"{peer_url}/index", 
            timeout=5,
            headers={"X-Auth-Token": AUTH_TOKEN}
        )
        if resp.status_code != 200: return
        remote_data = resp.json()
        
        remote_files = remote_data.get("files", {})
        remote_tombstones = remote_data.get("tombstones", {})

        scan_local_files() 
        local_files = LOCAL_STATE["files"] 

        # 2. Process Deletions
        for path, del_time in remote_tombstones.items():
            full_path = os.path.join(SYNC_DIR, path)
            if path in local_files:
                if del_time > local_files[path]["mtime"]:
                    print(f"[-] Applying remote deletion: {path}")
                    try:
                        if os.path.exists(full_path): os.remove(full_path)
                        with STATE_LOCK:
                            if path in LOCAL_STATE["files"]: del LOCAL_STATE["files"][path]
                            LOCAL_STATE["tombstones"][path] = del_time
                    except OSError: pass

        # 3. Process Updates / Downloads (PARALLELIZED)
        downloads = [] # List of (rel_path, r_meta, full_path)

        for rel_path, r_meta in remote_files.items():
            full_path = os.path.join(SYNC_DIR, rel_path)
            
            # CASE A: New file
            if rel_path not in local_files:
                my_del_time = LOCAL_STATE["tombstones"].get(rel_path, 0)
                if r_meta['mtime'] > my_del_time:
                    print(f"[+] Queueing new file: {rel_path}")
                    downloads.append((rel_path, r_meta, full_path))
                continue

            # CASE B: Update / Conflict
            local_meta = local_files[rel_path]
            if local_meta['hash'] == r_meta['hash']: continue

            # If Local is NEWER than Remote (by a margin), DO NOT touch it.
            # The remote peer will download it from us when it syncs.
            if local_meta['mtime'] > r_meta['mtime'] + 1:
                continue

            if r_meta['mtime'] > local_meta['mtime'] + 2:
                print(f"[^] Queueing update: {rel_path}")
                downloads.append((rel_path, r_meta, full_path))
            
            elif local_meta['hash'] != r_meta['hash']:
                print(f"[!] CONFLICT on {rel_path} -> Backing up")
                conflict_name = f"{full_path}.conflict-{MY_ID}-{int(time.time())}.bak"
                try:
                    os.rename(full_path, conflict_name)
                    downloads.append((rel_path, r_meta, full_path))
                except OSError: pass

        # Execute downloads in parallel
        if downloads:
            with ThreadPoolExecutor(max_workers=5) as executor:
                # We map the download function to the list of items
                # We need a helper to unpack arguments
                futures = [
                    executor.submit(download_and_save, peer_url, item[0], item[2], item[1]['mtime']) 
                    for item in downloads
                ]
                for f in futures: f.result() # Wait for all to finish

    except requests.exceptions.ConnectionError:
        pass
    except Exception as e:
        print(f"Error syncing with {peer_url}: {e}")

def download_and_save(peer_url, rel_path, dest_path, mtime):
    """Downloads a file atomically to prevent partial reads."""
    temp_path = dest_path + ".tmp"
    try:
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        
        # Download to .tmp file first
        with requests.get(
            f"{peer_url}/download/{rel_path}", 
            stream=True,
            headers={"X-Auth-Token": AUTH_TOKEN}
        ) as r:
            r.raise_for_status()
            with open(temp_path, 'wb') as f:
                for chunk in r.iter_content(chunk_size=16384):
                    f.write(chunk)
        
        # Apply timestamp to temp file
        os.utime(temp_path, (time.time(), mtime))
        
        # Atomic Rename (Overwrite)
        os.replace(temp_path, dest_path)
        
    except Exception as e:
        print(f"Failed to download {rel_path}: {e}")
        if os.path.exists(temp_path):
            try: os.remove(temp_path)
            except: pass

def run_sync_loop():
    print(f"--- Sync Active on: {SYNC_DIR} ---")
    
    # Start Watchdog
    event_handler = ChangeHandler()
    observer = Observer()
    observer.schedule(event_handler, SYNC_DIR, recursive=True)
    observer.start()
    
    try:
        while True:
            # Sync immediately
            scan_local_files()
            for peer in PEERS:
                sync_with_peer(peer)
            
            # Wait for event OR timeout (every 60s fallback instead of 15s)
            # If watchdog triggers, SYNC_EVENT is set, wait returns True immediately
            SYNC_EVENT.wait(timeout=60)
            SYNC_EVENT.clear()
            
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    t = threading.Thread(target=run_sync_loop, daemon=True)
    t.start()
    
    print(f"Starting server on port {PORT}...")
    uvicorn.run(app, host="0.0.0.0", port=PORT, log_level="error")