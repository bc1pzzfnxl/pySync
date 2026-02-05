# 🔄 pySync

> A lightweight, peer-to-peer file synchronization tool built in Python.

`pySync` is a minimalist alternative to tools like Syncthing, designed specifically for **Obsidian** vaults or small project synchronization over secure private networks (like **Tailscale**).

## 💡 Motivation

Why build this instead of using Syncthing or OneDrive?
-   **Control**: 100% Python, easy to audit and hack.
-   **Lightweight**: Designed to run comfortably on a Raspberry Pi Zero W or minimal VPS.
-   **No Third-Party Cloud**: Your data stays on your devices.
-   **Real-Time**: Integrates `watchdog` to trigger syncs instantly upon file save.
-   **Tailscale First**: Leveraging the security of a private mesh network, `pySync` focuses on logic rather than complex NAT traversal.

## 🚀 Features

-   **Real-time Synchronization**: Uses filesystem observers to detect changes immediately.
-   **Peer-to-Peer**: Every node is both a client and a server.
-   **Conflict Handling**:
    -   Smart timestamp comparison (Newer wins).
    -   Conflict backup generation (`.bak` files) if hashes differ but timestamps are ambiguous.
-   **Atomic Writes**: Downloads to `.tmp` files before renaming to prevent partial syncs.
-   **Optimized Network**:
    -   Push Notifications (Webhooks) from peers.
    -   Parallel Downloads (ThreadPoolExecutor) for fast small-file transfer.
-   **Security**: Token-based authentication (Bearer Token).

## 🛠️ Architecture

`pySync` works on a simple but robust loop:

1.  **Server (`FastAPI`)**: Exposes your file index (`/index`) and allows file download (`/download`).
2.  **Watcher (`Watchdog`)**: Monitors your folder. If a file changes:
    -   Updates local state (`pysync.db`).
    -   Notifies all peers via HTTP POST (`/notify`).
3.  **Syncer (Client)**:
    -   Wakes up on Notification (or every 60s).
    -   Fetches peer indexes.
    -   Compares local vs remote `mtime` (Modification Time).
    -   Downloads newer files (atomic replace).
    -   Propagates deletions (via "Tombstones" in `pysync.db`).

## 📦 Installation

**Requirements**: Python 3.8+

1.  Clone the repository:
    ```bash
    git clone https://github.com/your/repo.git pySync
    cd pySync
    ```

2.  Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```

3.  Configure `config.json` (See section below).

4.  Run:
    ```bash
    python pySync.py
    ```

## ⚙️ Configuration

Create a `config.json` file in the root directory:

```json
{
    "sync_dir": "C:/Users/You/Documents/ObsidianVault",
    "peers": [
        "100.x.y.z:7777",
        "100.a.b.c:7777"
    ],
    "auth_token": "YourSuperSecretPassword"
}
```
*   **sync_dir**: Absolute path to the folder you want to sync.
*   **peers**: List of `IP:Port` of your other machines (Tailscale IPs recommended).
*   **auth_token**: A master password shared across all your devices.

---

# 🚢 Deployment Guide

How to run `pySync` as a background service.

## 🐧 Linux (Raspberry Pi / Debian)

1.  **Edit** `deployment/pysync.service`:
    *   Change `User=pi` to your username.
    *   Change `WorkingDirectory` and `ExecStart` to match your installation path.

2.  **Install & Enable**:
    ```bash
    sudo cp deployment/pysync.service /etc/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable pysync
    sudo systemctl start pysync
    ```

3.  **Check Status**:
    ```bash
    systemctl status pysync
    journalctl -u pysync -f  # View logs
    ```

## 🪟 Windows

### Option 1: Startup Folder (Easiest)
1.  **Edit** `deployment/windows_startup.bat`:
    *   Update the path `cd /d "..."` to your folder.
2.  Press `Win + R`, type `shell:startup` and press Enter.
3.  Copy `windows_startup.bat` into this folder.
4.  It will start continuously in the background on next login.

### Option 2: Windows Service (Robust)
For a true service (starts before login), use **NSSM** (Non-Sucking Service Manager).
1.  Download [NSSM](https://nssm.cc/download).
2.  Run generic command line as Admin:
    ```powershell
    nssm install PySync
    ```
3.  In the GUI:
    *   **Path**: Path to your `python.exe`
    *   **Startup Directory**: Path to `pySync` folder
    *   **Arguments**: `pySync.py`
4.  Click "Install Service".
