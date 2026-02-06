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
    git clone https://github.com/bc1pzzfnxl/pySync.git
    cd pySync
    ```

2.  Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```

## 💻 Usage

Run the script directly via Command Line. No configuration file needed!

```bash
python pySync.py -d "C:/My/Folder" -t "IP_PEER1:7777" -t "IP_PEER2:7777" -p "MySecretPassword"
```

### Arguments:
*   `-d`, `--directory`: Path to the folder you want to sync (Absolute path recommended).
*   `-t`, `--target`: IP:Port of a peer. Can be used multiple times for multiple peers.
*   `-p`, `--password`: Shared secret for authentication.

### Example

**Machine A (10.0.0.1)** syncs `C:\Docs`:
```bash
python pySync.py -d "C:\Docs" -t "10.0.0.2:7777" -p "s3cr3t"
```

**Machine B (10.0.0.2)** syncs `/home/user/docs`:
```bash
python pySync.py -d "/home/user/docs" -t "10.0.0.1:7777" -p "s3cr3t"
```
