# gui/modern_siem.py

import sys
import os
import time
import threading
from datetime import datetime

from PySide6 import QtCore, QtWidgets
from PySide6.QtCore import Signal, Slot

from config.settings import settings
from core.alert_manager import AlertManager

# Import attack generator (handle file with dashes in name)
import importlib.util
import sys
from pathlib import Path

# Load the attacks-generator module
spec = importlib.util.spec_from_file_location(
    "attacks_generator",
    Path(__file__).parent / "attacks-generator.py"
)
attacks_generator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(attacks_generator)
AttackGenerator = attacks_generator.AttackGenerator

# Detecteurs
from detectors.sqli import detect as detect_sqli
from detectors.xss import detect as detect_xss

from detectors.bruteforce import detect as detect_bruteforce
from detectors.csrf import detect as detect_csrf
from detectors.file_upload import detect as detect_file_upload
from detectors.os_injection import detect as detect_os_injection
from detectors.crlf import detect as detect_crlf

DETECTORS = [detect_sqli, detect_xss, detect_bruteforce, detect_csrf, detect_file_upload, detect_os_injection, detect_crlf]


# =====================================================================
#   Signals
# =====================================================================
class AlertSignals(QtCore.QObject):
    new_alert = Signal(dict)
    stats_changed = Signal(dict)


# =====================================================================
#   MODERN SIEM WINDOW
# =====================================================================
class ModernSIEM(QtWidgets.QMainWindow):

    def __init__(self):
        super().__init__()
        self.setWindowTitle("SIEM – Modern Dashboard")
        self.resize(1100, 750)

        self.alert_manager = AlertManager()
        self.signals = AlertSignals()

        self.signals.new_alert.connect(self.add_alert_to_table)
        self.signals.stats_changed.connect(self.update_stats_cards)
        
        # Initialize attack generator
        self.attack_generator = AttackGenerator(sleep_interval=1)

        # stats internes
        self.stats = {
            "SQL Injection": 0,
            "XSS": 0,
            "Brute Force": 0,
            "Others": 0,
            "Total": 0
        }

        # stockage des alertes
        self.all_alerts = []

        self.build_ui()
        self.start_watcher()

    # -----------------------------------------------------------
    #   UI
    # -----------------------------------------------------------
    def build_ui(self):
        central = QtWidgets.QWidget()
        self.setCentralWidget(central)

        layout = QtWidgets.QVBoxLayout(central)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(12)

        # ============ STAT CARDS =============
        cards = QtWidgets.QHBoxLayout()
        cards.setSpacing(12)
        layout.addLayout(cards)

        self.card_sqli = self.create_card("SQL Injection")
        self.card_xss = self.create_card("XSS")
        self.card_bruteforce = self.create_card("Brute Force")
        self.card_total = self.create_card("Total Attacks", big=True)

        cards.addWidget(self.card_sqli)
        cards.addWidget(self.card_xss)
        cards.addWidget(self.card_bruteforce)
        cards.addWidget(self.card_total)

        # ============ FILTER BAR =============
        filter_layout = QtWidgets.QHBoxLayout()
        layout.addLayout(filter_layout)

        self.filter_box = QtWidgets.QComboBox()
        self.filter_box.addItems(["All", "SQL Injection", "XSS", "Brute Force", "CSRF", "File Upload", "OS Injection", "CRLF"])
        self.filter_box.currentTextChanged.connect(self.apply_filter)

        filter_layout.addWidget(QtWidgets.QLabel("Filtrer par type:"))
        filter_layout.addWidget(self.filter_box)
        filter_layout.addStretch()
        
        # Attack Generator Controls
        self.generator_status_label = QtWidgets.QLabel("Générateur: Arrêté")
        self.generator_status_label.setStyleSheet("font-weight:600; color:#ff6b6b;")
        filter_layout.addWidget(self.generator_status_label)
        
        self.start_generator_btn = QtWidgets.QPushButton("▶ Démarrer Attaques")
        self.start_generator_btn.setStyleSheet(
            "background-color:#51cf66; color:white; font-weight:600; padding:8px 16px; border-radius:4px;"
        )
        self.start_generator_btn.clicked.connect(self.start_attack_generator)
        filter_layout.addWidget(self.start_generator_btn)
        
        self.stop_generator_btn = QtWidgets.QPushButton("⏸ Arrêter Attaques")
        self.stop_generator_btn.setStyleSheet(
            "background-color:#ff6b6b; color:white; font-weight:600; padding:8px 16px; border-radius:4px;"
        )
        self.stop_generator_btn.clicked.connect(self.stop_attack_generator)
        self.stop_generator_btn.setEnabled(False)
        filter_layout.addWidget(self.stop_generator_btn)

        # ============ TABLE ALERTES =============
        self.table = QtWidgets.QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Timestamp", "Type", "Pattern", "Line"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        layout.addWidget(self.table, stretch=1)

        # ============ LIVE LOG VIEW =============
        self.log_view = QtWidgets.QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumHeight(150)
        layout.addWidget(self.log_view)

    # -----------------------------------------------------------
    #   CARD TEMPLATE
    # -----------------------------------------------------------
    def create_card(self, title, big=False):
        frame = QtWidgets.QFrame()
        frame.setFrameShape(QtWidgets.QFrame.StyledPanel)
        layout = QtWidgets.QVBoxLayout(frame)

        title_label = QtWidgets.QLabel(title)
        title_label.setStyleSheet("font-weight:600; font-size:13px; color:#ddd;")

        count_label = QtWidgets.QLabel("0")
        count_label.setStyleSheet(
            f"font-size:{22 if big else 18}px; font-weight:700; color:white;"
        )

        pct_label = QtWidgets.QLabel("0%")
        pct_label.setStyleSheet("color:#cccccc;")

        layout.addWidget(title_label)
        layout.addWidget(count_label)
        layout.addWidget(pct_label)

        frame._count = count_label
        frame._pct = pct_label
        return frame

    # -----------------------------------------------------------
    #   UPDATE CARDS
    # -----------------------------------------------------------
    @Slot(dict)
    def update_stats_cards(self, stats):
        total = max(stats["Total"], 1)

        def update(card, value):
            pct = round((value / total) * 100)
            card._count.setText(str(value))
            card._pct.setText(f"{pct}%")

        update(self.card_sqli, stats["SQL Injection"])
        update(self.card_xss, stats["XSS"])
        update(self.card_bruteforce, stats["Brute Force"])

        self.card_total._count.setText(str(stats["Total"]))
        self.card_total._pct.setText("100%")

    # -----------------------------------------------------------
    #   TABLE ALERT
    # -----------------------------------------------------------
    @Slot(dict)
    def add_alert_to_table(self, alert):
        self.all_alerts.append(alert)
        self.apply_filter()

    def apply_filter(self):
        selected = self.filter_box.currentText()
        self.table.setRowCount(0)

        for a in self.all_alerts:
            if selected != "All" and a["type"] != selected:
                continue

            row = self.table.rowCount()
            self.table.insertRow(row)

            self.table.setItem(row, 0, QtWidgets.QTableWidgetItem(a["timestamp"]))
            self.table.setItem(row, 1, QtWidgets.QTableWidgetItem(a["type"]))
            self.table.setItem(row, 2, QtWidgets.QTableWidgetItem(a["pattern"]))
            self.table.setItem(row, 3, QtWidgets.QTableWidgetItem(a["line"]))

    # -----------------------------------------------------------
    #   WATCH LOG FILE
    # -----------------------------------------------------------
    def start_watcher(self):
        thread = threading.Thread(target=self.watcher_loop, daemon=True)
        thread.start()

    def watcher_loop(self):
        log_path = settings.ACCESS_LOG_PATH
        last_pos = 0

        while True:
            try:
                if not os.path.exists(log_path):
                    time.sleep(1)
                    continue

                with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
                    f.seek(last_pos)
                    for line in f:
                        stripped = line.strip()
                        self.log_view.appendPlainText(stripped)

                        for detect in DETECTORS:
                            found, pattern, attack_type = detect(line)
                            if not found:
                                continue

                            # Convert list of patterns to string if necessary
                            if isinstance(pattern, list):
                                pattern = ", ".join(str(p) for p in pattern)

                            # enregistrer
                            self.alert_manager.log_alert(attack_type, pattern, line)

                            alert = {
                                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                "type": attack_type,
                                "pattern": pattern,
                                "line": stripped
                            }

                            # update stats
                            if attack_type in self.stats:
                                self.stats[attack_type] += 1
                            else:
                                self.stats["Others"] += 1

                            self.stats["Total"] += 1

                            self.signals.new_alert.emit(alert)
                            self.signals.stats_changed.emit(self.stats)

                    last_pos = f.tell()

                time.sleep(settings.SLEEP_INTERVAL)

            except Exception as e:
                print("Watcher error:", e)
                time.sleep(1)
    
    # -----------------------------------------------------------
    #   ATTACK GENERATOR CONTROLS
    # -----------------------------------------------------------
    def start_attack_generator(self):
        """Start the attack generator."""
        self.attack_generator.start()
        self.generator_status_label.setText("Générateur: En cours")
        self.generator_status_label.setStyleSheet("font-weight:600; color:#51cf66;")
        self.start_generator_btn.setEnabled(False)
        self.stop_generator_btn.setEnabled(True)
        self.log_view.appendPlainText("[SYSTEM] Générateur d'attaques démarré")
    
    def stop_attack_generator(self):
        """Stop the attack generator."""
        self.attack_generator.stop()
        self.generator_status_label.setText("Générateur: Arrêté")
        self.generator_status_label.setStyleSheet("font-weight:600; color:#ff6b6b;")
        self.start_generator_btn.setEnabled(True)
        self.stop_generator_btn.setEnabled(False)
        self.log_view.appendPlainText("[SYSTEM] Générateur d'attaques arrêté")
    
    def closeEvent(self, event):
        """Handle window close event - stop generator if running."""
        if self.attack_generator.is_running():
            self.attack_generator.stop()
        event.accept()


# =====================================================================
#   RUN
# =====================================================================
def run_app():
    app = QtWidgets.QApplication(sys.argv)
    window = ModernSIEM()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    run_app()
