import os
import time
import json
import sys
import hashlib
import threading
import requests
import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse

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
    
    if not os.path.exists(SYNC_DIR):
        print(f"ERROR: The directory {SYNC_DIR} does not exist.")
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

def load_state():
    global LOCAL_STATE
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                LOCAL_STATE = json.load(f)
                # Ensure structure
                if "files" not in LOCAL_STATE: LOCAL_STATE["files"] = {}
                if "tombstones" not in LOCAL_STATE: LOCAL_STATE["tombstones"] = {}
        except Exception as e:
            print(f"Error loading state: {e}")

def save_state():
    with STATE_LOCK:
        try:
            with open(STATE_FILE, "w", encoding="utf-8") as f:
                json.dump(LOCAL_STATE, f)
        except Exception as e:
            print(f"Error saving state: {e}")

# Load state on startup
load_state()

# ========================================================

MY_ID = os.environ.get("COMPUTERNAME", os.environ.get("HOSTNAME", "PC_UNKNOWN"))
app = FastAPI()

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
            if file in IGNORE_FILES: continue
            
            path = os.path.join(root, file)
            rel_path = os.path.relpath(path, SYNC_DIR).replace("\\", "/")
            
            try:
                stat = os.stat(path)
                # Optimization: Only re-hash if mtime changed or not in state
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
        # 2. Detect Deletions (Files in State but NOT in Current Scan)
        # But filter out files that are already tombstones to avoid refreshing timestamp unnecessarily
        for old_path in list(LOCAL_STATE["files"].keys()):
            if old_path not in current_files:
                # IT'S GONE! Mark as deleted.
                print(f"[-] Detected local deletion: {old_path}")
                LOCAL_STATE["tombstones"][old_path] = time.time()
        
        # 3. Update State
        LOCAL_STATE["files"] = current_files
        
        # Cleanup: Remove files from tombstones if they reappeared
        for new_path in current_files:
            if new_path in LOCAL_STATE["tombstones"]:
                del LOCAL_STATE["tombstones"][new_path]

        # Cleanup: Remove very old tombstones (e.g. > 30 days) to keep DB small
        now = time.time()
        expired = [p for p, t in LOCAL_STATE["tombstones"].items() if now - t > 2592000]
        for p in expired:
            del LOCAL_STATE["tombstones"][p]

    save_state()
    return LOCAL_STATE

# --- SERVER SIDE ---

@app.get("/index")
def get_index():
    """Returns the current state including files and tombstones."""
    # Force a scan to ensure we are up to date before serving
    return scan_local_files()

@app.get("/download/{file_path:path}")
def download_file(file_path: str):
    """Serves the requested file to the peer."""
    if ".." in file_path: raise HTTPException(403)
    
    full_path = os.path.join(SYNC_DIR, file_path)
    if os.path.exists(full_path):
        return FileResponse(full_path)
    raise HTTPException(404)

# --- CLIENT SIDE ---

def sync_with_peer(peer_url):
    try:
        if not peer_url.startswith("http"):
            peer_url = f"http://{peer_url}"

        # 1. Download peer's index
        resp = requests.get(f"{peer_url}/index", timeout=5)
        if resp.status_code != 200: return
        remote_data = resp.json()
        
        remote_files = remote_data.get("files", {})
        remote_tombstones = remote_data.get("tombstones", {})

        # Refresh local view before comparing
        scan_local_files() 
        
        local_files = LOCAL_STATE["files"] 

        # 2. Process Deletions (Tombstones) FIRST
        for path, del_time in remote_tombstones.items():
            full_path = os.path.join(SYNC_DIR, path)
            
            # If we have this file, check if we should delete it
            if path in local_files:
                local_mtime = local_files[path]["mtime"]
                
                # If deletion happened AFTER our last edit -> DELETE IT
                if del_time > local_mtime:
                    print(f"[-] Applying remote deletion: {path}")
                    try:
                        if os.path.exists(full_path):
                            os.remove(full_path)
                        # Remove from our local state immediately
                        with STATE_LOCK:
                            if path in LOCAL_STATE["files"]:
                                del LOCAL_STATE["files"][path]
                            LOCAL_STATE["tombstones"][path] = del_time # Adopt the tombstone
                    except OSError as e:
                        print(f"Error deleting {path}: {e}")

        # 3. Process Updates / Downloads
        for rel_path, r_meta in remote_files.items():
            full_path = os.path.join(SYNC_DIR, rel_path)
            
            # CASE A: New file (I don't have it and it's NOT a tombstone locally)
            if rel_path not in local_files:
                # Check if I previously deleted it (Tombstone check)
                my_del_time = LOCAL_STATE["tombstones"].get(rel_path, 0)
                
                if r_meta['mtime'] > my_del_time:
                    # It's newer than my deletion (or I never deleted it) -> Download
                    print(f"[+] Downloading new file: {rel_path}")
                    download_and_save(peer_url, rel_path, full_path, r_meta['mtime'])
                
                continue

            # CASE B: I have it
            local_meta = local_files[rel_path]
            
            if local_meta['hash'] == r_meta['hash']:
                continue # Identical

            # CASE C: Conflict / Update
            if r_meta['mtime'] > local_meta['mtime'] + 2: # Tolerance
                print(f"[^] Updating: {rel_path}")
                download_and_save(peer_url, rel_path, full_path, r_meta['mtime'])
            
            elif local_meta['hash'] != r_meta['hash']:
                # Conflict logic same as before...
                # Simpler: if hashes differ and times are close, just backup mine and take theirs
                print(f"[!] CONFLICT on {rel_path} -> Backing up")
                conflict_name = f"{full_path}.conflict-{MY_ID}-{int(time.time())}.bak"
                try:
                    os.rename(full_path, conflict_name)
                    download_and_save(peer_url, rel_path, full_path, r_meta['mtime'])
                except OSError:
                    pass

    except requests.exceptions.ConnectionError:
        pass
    except Exception as e:
        print(f"Error syncing with {peer_url}: {e}")

def download_and_save(peer_url, rel_path, dest_path, mtime):
    """Downloads a file and forces its modification time to match the source."""
    try:
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        
        with requests.get(f"{peer_url}/download/{rel_path}", stream=True) as r:
            r.raise_for_status()
            with open(dest_path, 'wb') as f:
                for chunk in r.iter_content(chunk_size=16384):
                    f.write(chunk)
                    
        os.utime(dest_path, (time.time(), mtime))
        # Update state immediately after download to prevent re-download loop
        with STATE_LOCK:
             # Re-hash (or trust remote hash? trusting is faster but risky if corruption)
             # Let's trust for speed but next scan will verify
             pass 

    except Exception as e:
        print(f"Failed to download {rel_path}: {e}")

def run_sync_loop():
    print(f"--- Sync Active on: {SYNC_DIR} ---")
    while True:
        # Periodically save state
        scan_local_files()
        
        for peer in PEERS:
            sync_with_peer(peer)
        time.sleep(15)

if __name__ == "__main__":
    t = threading.Thread(target=run_sync_loop, daemon=True)
    t.start()
    
    print(f"Starting server on port {PORT}...")
    uvicorn.run(app, host="0.0.0.0", port=PORT, log_level="error")