# Multi-Instance Launcher with Auto-Update

A small Python launcher that:

- Starts multiple instances of a target executable (one line of arguments per instance).
- Monitors instances and automatically restarts any that exit.
- Periodically checks a remote JSON (HTTPS) for updates containing `{ "sha256": "...", "file": "..." }`.
- If the remote SHA256 differs from the local executable, downloads the new binary, verifies SHA256, gracefully stops all instances (SIGTERM → SIGKILL), atomically replaces the binary, and restarts all instances.
- Can use compressed archives instead of simple executables. In archive mode, when an update starts, the archive is downloaded and extracted, then a configurable executable inside the extracted archive is launched.

## Quick start

1. Copy `config_example.json` to `config.json` and adjust your settings.
2. Fill `instances.txt` (one arguments line per instance).
3. Run:

```bash
python3 launcher.py
```

## `config.json` format

- `executable`: Path of the executable to launch. In archive mode (see "compressed_archive"), path must be relative to archive root.
- `compressed_archive`: null to use a simple executable, or path to the compressed archive when using archive mode.
- `extract_dir`: Path of the directory used to extract compressed archive when using archive mode, ignored otherwise.
- `instances_file`: Path of the instances file.
- `check_interval_s`: Interval in seconds to check for updates.
- `restart_delay_s`: Delay in seconds inserted before restart a stopped instance.
- `stop_grace_s`: Waiting time in seconds after sending SIGTERM before sending SIGKILL if the process does not terminate.
- `update_json_url`: URL of the remote JSON file used to check for updates
- `download_base_url`: The base URL used to access the update file. The value of the "file" key from the remote JSON file is added to this base to construct the update file URL.
