#!/usr/bin/env python3
"""
Launcher: launch N instances, auto-restart, manage updates via HTTPS JSON.
"""

import ctypes
import signal
import os
import sys
import time
import json
import hashlib
import shutil
import tempfile
import threading
import subprocess
import urllib.request
import logging
import argparse
from pathlib import Path


# --- Logging ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("launcher")

# --- Load config ---
DEFAULT_CONFIG = {
    "executable": "myprogram.exe",
    "instances_file": "instances.txt",
    "check_interval_s": 1800,
    "restart_delay_s": 15,
    "stop_grace_s": 10,
    "update_json_url": "https://example.com/update.json",
    "download_base_url": "https://example.com/binaries/",
}

def load_config(path="config.json"):
    logger.info("Loading config from %s", path)
    with open(path, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    for k,v in DEFAULT_CONFIG.items():
        cfg.setdefault(k, v)
    return cfg

# --- Utilities ---
def sha256_of_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024*1024), b""):
            h.update(chunk)
    return h.hexdigest()

def download_file(url, dst_path):
    logger.info("Download %s -> %s", url, dst_path)
    with urllib.request.urlopen(url) as resp:
        if resp.status != 200:
            raise RuntimeError(f"Download failed, status {resp.status}")
        with open(dst_path, "wb") as out:
            shutil.copyfileobj(resp, out)
    return dst_path

# --- Process management ---
def pdeathsig_kill():   # to ensure child dies if parent dies
    libc = ctypes.CDLL("libc.so.6")
    PR_SET_PDEATHSIG = 1
    libc.prctl(PR_SET_PDEATHSIG, signal.SIGKILL)
    
class Instance:
    def __init__(self, args_line, exec_path):
        self.args_line = args_line.strip()
        self.exec_path = exec_path
        self.proc = None
        self.lock = threading.Lock()

    def start(self):
        with self.lock:
            cmd = [str(self.exec_path)] + (self.args_line.split() if self.args_line else [])
            logger.info("Start: %s", " ".join(cmd))
            self.proc = subprocess.Popen(cmd, preexec_fn=pdeathsig_kill)

    def is_running(self):
        with self.lock:
            return self.proc is not None and self.proc.poll() is None

    def terminate(self, grace):
        with self.lock:
            if self.proc is None:
                return
            try:
                logger.info("SIGTERM to pid %s", self.proc.pid)
                self.proc.terminate()  # sends SIGTERM
            except Exception as e:
                logger.exception("Error terminate: %s", e)
            # wait up to grace seconds
            try:
                self.proc.wait(timeout=grace)
            except subprocess.TimeoutExpired:
                logger.warning("Process %s did not exit after %s s -> kill", self.proc.pid, grace)
                try:
                    os.kill(self.proc.pid, 9)
                except Exception as e:
                    logger.exception("Error kill: %s", e)
                try:
                    self.proc.wait(timeout=5)
                except Exception:
                    logger.exception("Process still alive after kill")
            finally:
                self.proc = None

# --- Launcher controller ---
class Launcher:
    def __init__(self, cfg):
        self.cfg = cfg
        self.exec_path = Path(cfg["executable"]).resolve()
        self.instances = []
        self.stop_event = threading.Event()
        self.monitor_thread = None
        self.updater_thread = None
        self.instances_lock = threading.Lock()
        self.load_instances()
        self.current_sha = self.compute_local_sha()

    def load_instances(self):
        inst_file = self.cfg["instances_file"]
        self.instances = []
        if os.path.exists(inst_file):
            with open(inst_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    self.instances.append(Instance(line, self.exec_path))
        else:
            logger.warning("instances_file %s not found. No instances loaded.", inst_file)

    def compute_local_sha(self):
        if not self.exec_path.exists():
            return None
        try:
            return sha256_of_file(self.exec_path)
        except Exception as e:
            logger.exception("Error computing local SHA: %s", e)
            return None

    def start_all(self):
        with self.instances_lock:
            for inst in self.instances:
                inst.start()

    def stop_all(self):
        grace = self.cfg.get("stop_grace_s", 10)
        logger.info("Stopping all instances (grace %s s)", grace)
        with self.instances_lock:
            for inst in list(self.instances):
                try:
                    inst.terminate(grace)
                except Exception as e:
                    logger.exception("Error stopping instance: %s", e)

    def monitor_loop(self):
        restart_delay = self.cfg.get("restart_delay_s", 5)
        while not self.stop_event.is_set():
            with self.instances_lock:
                for inst in self.instances:
                    if not inst.is_running():
                        logger.warning("Instance dead: '%s' -> restart in %ss", inst.args_line, restart_delay)
                        try:
                            time.sleep(restart_delay)
                            if self.stop_event.is_set():
                                break
                            inst.start()
                        except Exception as e:
                            logger.exception("Error restarting instance: %s", e)
            time.sleep(1)

    def updater_loop(self):
        check_interval = self.cfg.get("check_interval_s", 60)
        update_url = self.cfg["update_json_url"]
        base_download = self.cfg.get("download_base_url", "")
        while not self.stop_event.is_set():
            try:
                logger.info("Checking for update: %s", update_url)
                with urllib.request.urlopen(update_url, timeout=30) as r:
                    if r.status != 200:
                        logger.warning("Update JSON status %s", r.status)
                    else:
                        data = json.load(r)
                        new_sha = data.get("sha256")
                        filename = data.get("file")
                        if new_sha and filename:
                            if new_sha != self.current_sha:
                                logger.info("New version detected: local sha=%s, remote sha=%s", self.current_sha, new_sha)
                                full_url = base_download + filename
                                if self.perform_update(full_url, new_sha):
                                    self.current_sha = new_sha
                            else:
                                logger.debug("No new version (sha identical).")
                        else:
                            logger.warning("Invalid JSON: missing 'sha256' or 'file'")
            except Exception as e:
                logger.exception("Error checking update: %s", e)
            # sleep with early exit
            for _ in range(int(check_interval)):
                if self.stop_event.is_set():
                    break
                time.sleep(1)

    def perform_update(self, download_url, expected_sha):
        logger.info("Update: downloading from %s", download_url)
        tmp_dir = tempfile.mkdtemp(prefix="launcher_update_")
        try:
            tmp_file = Path(tmp_dir) / ("new_exec.bin")
            download_file(download_url, tmp_file)
            # check sha
            got_sha = sha256_of_file(tmp_file)
            if got_sha != expected_sha:
                logger.error("SHA mismatch: expected=%s, got=%s -- aborting", expected_sha, got_sha)
                return False
            # stop instances
            logger.info("Stopping instances before replacing binary")
            self.stop_all()
            # replace executable atomically
            target = self.exec_path
            backup = target.with_suffix(target.suffix + ".bak")
            try:
                if target.exists():
                    logger.info("Creating backup %s", backup)
                    os.replace(str(target), str(backup))  # atomic on same FS
                # move new file in place
                os.replace(str(tmp_file), str(target))
                # ensure executable bit
                target.chmod(0o755)
                logger.info("Replacement successful: %s", target)
            except Exception as e:
                logger.exception("Error replacing binary: %s", e)
                # try to restore backup
                if backup.exists():
                    os.replace(str(backup), str(target))
                    logger.info("Backup restored")
                return False
            finally:
                # cleanup backup
                if backup.exists():
                    try:
                        backup.unlink()
                    except Exception:
                        pass
            # restart all
            logger.info("Restarting all instances with the new binary")
            self.start_all()
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)
        return True

    def start(self):
        logger.info("Launcher starting")
        self.start_all()
        # start monitor thread
        self.monitor_thread = threading.Thread(target=self.monitor_loop, daemon=True)
        self.monitor_thread.start()
        # start updater
        self.updater_thread = threading.Thread(target=self.updater_loop, daemon=True)
        self.updater_thread.start()

    def stop(self):
        logger.info("Launcher stopping")
        self.stop_event.set()
        # stop instances
        self.stop_all()
        # join threads
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)
        if self.updater_thread:
            self.updater_thread.join(timeout=2)
        logger.info("Launcher stopped.")

# --- Signal handling ---
def install_signal_handlers(launcher):
    shutting_down = False
    lock = threading.Lock()

    def handler(signum, frame):
        nonlocal shutting_down
        with lock:
            if shutting_down:
                return
            shutting_down = True

        logger.info(f"Received signal {signum}")
        launcher.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)

# --- Main ---
def main(cfg_path):
    cfg = load_config(cfg_path)
    launcher = Launcher(cfg)
    install_signal_handlers(launcher)
    launcher.start()
    while True:
        time.sleep(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Multi-instance launcher with auto-update")
    parser.add_argument("--config", type=str, default="config.json", help="JSON config file path")
    args = parser.parse_args()

    main(args.config)
