"""
Firewall Control & Alert System.
Run as Administrator on Window
"""

import sys
import os
import subprocess
import time
import re
import ctypes
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QTextEdit,
    QMessageBox, QInputDialog, QLabel, QHBoxLayout
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QObject

LOG_PATH = r"C:\Temp\pfirewall.log"
THRESHOLD = 3      
WINDOW = 60        
WHITELIST = {"127.0.0.1", "0.0.0.0", "192.168.56.1"}

ip_re = re.compile(r'(\d+\.\d+\.\d+\.\d+)')

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def run_cmd(cmd):
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-Command", cmd],
            capture_output=True, text=True, shell=False, timeout=20
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except Exception as e:
        return 1, "", str(e)

def set_firewall(state):
    cmd = f'netsh advfirewall set allprofiles state {"on" if state else "off"}'
    return run_cmd(cmd)

def enable_logging():
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    cmds = [
        f'netsh advfirewall set currentprofile logging filename "{LOG_PATH}"',
        'netsh advfirewall set currentprofile logging maxfilesize 16384',
        'netsh advfirewall set currentprofile logging droppedconnections enable',
        'netsh advfirewall set currentprofile logging allowedconnections enable'
    ]
    for c in cmds:
        rc, out, err = run_cmd(c)
        if rc != 0:
            return False, err
    return True, f"Logging enabled -> {LOG_PATH}"

def block_ip(ip):
    if ip in WHITELIST:
        return False, f"{ip} is whitelisted!"
    if not re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
        return False, "Invalid IP address."
    rule_name = f"Block_{ip}_{int(time.time())}"
    cmd = f'New-NetFirewallRule -DisplayName "{rule_name}" -Direction Inbound -Action Block -RemoteAddress {ip}'
    rc, out, err = run_cmd(cmd)
    if rc == 0:
        return True, f"✅ Block rule created for {ip}"
    else:
        return False, err

class LogWatcherWorker(QObject):
    line_signal = pyqtSignal(str)  
    alert_signal = pyqtSignal(str)  
    info_signal = pyqtSignal(str)    

    def __init__(self, log_path=LOG_PATH, threshold=THRESHOLD, window=WINDOW):
        super().__init__()
        self.log_path = log_path
        self.threshold = threshold
        self.window = window
        self._running = False
        self.ip_times = {}

    def start(self):
        self._running = True
        self._run()

    def stop(self):
        self._running = False

    def _run(self):
        try:
            if not os.path.exists(self.log_path):
                self.info_signal.emit("⚠️ Log file not found. Click 'Enable Logging' first.")
                return

            with open(self.log_path, "r", errors="ignore") as f:
                f.seek(0, os.SEEK_END)
                while self._running:
                    line = f.readline()
                    if not line:
                        time.sleep(0.5)
                        continue
                    text = line.strip()
                    self.line_signal.emit(text)

                    m = ip_re.search(text)
                    if m:
                        ip = m.group(1)
                        now = time.time()
                        times = self.ip_times.setdefault(ip, [])
                        times.append(now)
                        times = [t for t in times if now - t <= self.window]
                        self.ip_times[ip] = times
                        if len(times) >= self.threshold:
                            self.ip_times[ip] = []
                            self.alert_signal.emit(ip)

        except Exception as e:
            self.info_signal.emit(f"⚠️ Watcher error: {e}")
            while self._running:
                time.sleep(1)

class FirewallApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🛡 Firewall Control & Alert System")
        self.setGeometry(200, 120, 900, 520)
        self.setup_ui()
        self.thread = None
        self.worker = None
        self.start_watcher_thread_if_admin()

    def setup_ui(self):
        self.setStyleSheet("""
            QWidget { background-color: #FFFFFF; color: #222; font-family: Segoe UI; font-size: 10pt; }
            QPushButton { background-color: #E9E9E9; border: 1px solid #CCC; border-radius:6px; padding:6px 12px; }
            QPushButton:hover { background-color: #0078d7; color: white; }
            QTextEdit { background-color: #F8F9FA; border:1px solid #CCC; border-radius:6px; font-family:Consolas; font-size:9pt; }
            QLabel { padding:4px; font-weight: bold; }
        """)

        main_layout = QVBoxLayout()
        btn_layout = QHBoxLayout()

        self.btn_off = QPushButton("Turn Firewall OFF (Before)")
        self.btn_on = QPushButton("Turn Firewall ON (After)")
        self.btn_log = QPushButton("Enable Logging")
        self.btn_tail = QPushButton("Show Log Tail (20)")
        self.btn_block = QPushButton("Block IP")

        for b in (self.btn_off, self.btn_on, self.btn_log, self.btn_tail, self.btn_block):
            btn_layout.addWidget(b)

        self.output = QTextEdit()
        self.output.setReadOnly(True)
        self.status_label = QLabel("Status: Ready")

        main_layout.addLayout(btn_layout)
        main_layout.addWidget(self.output)
        main_layout.addWidget(self.status_label)
        self.setLayout(main_layout)

        self.btn_on.clicked.connect(lambda: self.toggle_firewall(True))
        self.btn_off.clicked.connect(lambda: self.toggle_firewall(False))
        self.btn_log.clicked.connect(self.do_enable_logging)
        self.btn_tail.clicked.connect(self.show_log_tail)
        self.btn_block.clicked.connect(self.do_block_ip)

    def append_output(self, text):
        self.output.append(f"[{time.strftime('%H:%M:%S')}] {text}")
        self.output.ensureCursorVisible()

    def alert_detected(self, ip):
        self.append_output(f"⚠️ ALERT: Multiple connection attempts from {ip}")
        QMessageBox.warning(self, "Scan Detected", f"Multiple attempts detected from {ip}")

    def info_message(self, msg):
        self.append_output(msg)

    def toggle_firewall(self, state):
        state_str = "ON" if state else "OFF"
        self.append_output(f"Toggling firewall {state_str}...")
        rc, out, err = set_firewall(state)
        if rc == 0:
            self.append_output(f"Firewall {state_str} ✅")
            self.status_label.setText(f"Firewall: {state_str}")
        else:
            self.append_output(f"Error: {err}")

    def do_enable_logging(self):
        ok, msg = enable_logging()
        self.append_output(msg if ok else f"Error: {msg}")
        if ok:
            self.restart_watcher_if_needed()

    def show_log_tail(self):
        if not os.path.exists(LOG_PATH):
            self.append_output("⚠️ No log file found.")
            return
        try:
            with open(LOG_PATH, "r", errors="ignore") as f:
                lines = f.readlines()
            self.append_output("---- Last 20 Log Lines ----")
            for line in lines[-20:]:
                self.append_output(line.strip())
            self.append_output("---- End ----")
        except Exception as e:
            self.append_output(f"Error reading log: {e}")

    def do_block_ip(self):
        ip, ok = QInputDialog.getText(self, "Block IP", "Enter IP to block:")
        if ok and ip:
            if ip in WHITELIST:
                QMessageBox.information(self, "Whitelisted", f"{ip} is whitelisted.")
                return
            confirm = QMessageBox.question(self, "Confirm", f"Block all traffic from {ip}?")
            if confirm == QMessageBox.Yes:
                success, msg = block_ip(ip)
                self.append_output(msg)
                if success:
                    QMessageBox.information(self, "Blocked", f"{ip} blocked successfully.")
                else:
                    QMessageBox.warning(self, "Error", msg)

    def start_watcher_thread_if_admin(self):
        if not is_admin():
            self.append_output("⚠️ Not running as Administrator. Run elevated for full control.")
            QMessageBox.warning(self, "Admin Needed", "Run this program as Administrator for full control.")
            return

        self.thread = QThread()
        self.worker = LogWatcherWorker(LOG_PATH, THRESHOLD, WINDOW)
        self.worker.moveToThread(self.thread)

        self.thread.started.connect(self.worker.start)
        self.worker.line_signal.connect(self.append_output)
        self.worker.alert_signal.connect(self.alert_detected)
        self.worker.info_signal.connect(self.info_message)

        self.thread.finished.connect(self.thread.deleteLater)

        self.thread.start()
        self.append_output("✅ Log watcher thread started (admin mode).")

    def restart_watcher_if_needed(self):
        if self.thread and self.thread.isRunning():
            return
        self.start_watcher_thread_if_admin()

    def stop_watcher(self):
        if self.worker:
            try:
                self.worker.stop()
            except Exception:
                pass
        if self.thread:
            try:
                self.thread.quit()
                self.thread.wait(2000)
            except Exception:
                pass

    def closeEvent(self, event):
        reply = QMessageBox.question(
            self, "Exit Confirmation",
            "Are you sure you want to close the Firewall Dashboard?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            self.stop_watcher()
            event.accept()
        else:
            event.ignore()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = FirewallApp()
    win.show()
    app.exec_()