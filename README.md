# Multi-Instance Launcher with Auto-Update

A small Python launcher that:

- Starts multiple instances of a target executable (one line of arguments per instance).
- Monitors instances and automatically restarts any that exit.
- Periodically checks a remote JSON (HTTPS) for updates containing `{ "sha256": "...", "file": "..." }`.
- If the remote SHA256 differs from the local executable, downloads the new binary, verifies SHA256, gracefully stops all instances (SIGTERM → SIGKILL), atomically replaces the binary, and restarts all instances.

## Quick start

1. Copy `config_example.json` to `config.json` and adjust your settings.
2. Fill `instances.txt` (one arguments line per instance).
3. Run:

```bash
python3 launcher.py
