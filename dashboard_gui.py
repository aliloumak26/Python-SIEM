# gui/modern_siem.py

import sys
import os
import time
import threading
from datetime import datetime

from PySide6 import QtCore, QtWidgets, QtGui
from PySide6.QtCore import Signal, Slot, Qt
from PySide6.QtWidgets import QScrollArea

from config.settings import settings
from core.alert_manager import AlertManager

# Import attack generator
from attacks_generator import AttackGenerator

# Detecteurs
from detectors.sqli import detect as detect_sqli
from detectors.xss import detect as detect_xss

from detectors.bruteforce import detect as detect_bruteforce
from detectors.csrf import detect as detect_csrf
from detectors.file_upload import detect as detect_file_upload
from detectors.os_injection import detect as detect_os_injection
from detectors.crlf import detect as detect_crlf
from detectors.ip import detect_ip_reputation

# ML Anomaly Detector
from ml.anomaly_detector import AnomalyDetector

from PySide6.QtWebEngineWidgets import QWebEngineView
import folium
import io
from geo_finder import get_ip_info
from PySide6.QtCharts import QChart, QChartView, QPieSeries, QPieSlice

DETECTORS = [detect_sqli, detect_xss, detect_bruteforce, detect_csrf, detect_file_upload, detect_os_injection, detect_crlf, detect_ip_reputation]


# =====================================================================
#   MODERN DARK THEME STYLESHEET
# =====================================================================
DARK_STYLESHEET = """
QMainWindow {
    background-color: #0f1419;
}

QWidget {
    font-family: 'Segoe UI', sans-serif;
    font-size: 13px;
    color: #e7e9ea;
}

QScrollArea {
    border: none;
    background: transparent;
}

QScrollArea > QWidget > QWidget {
    background: transparent;
}

/* ============ STAT CARDS ============ */
QFrame#StatCard {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 #1a1f2e, stop:1 #141824);
    border: 1px solid #2a3441;
    border-radius: 10px;
    padding: 14px;
}

QFrame#StatCard:hover {
    border: 1px solid #3b82f6;
}

QFrame#StatCardDanger {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 #2a1a1f, stop:1 #1e1418);
    border: 1px solid #7f1d1d;
    border-radius: 10px;
    padding: 14px;
}

QFrame#StatCardDanger:hover {
    border: 1px solid #ef4444;
}

QFrame#StatCardSuccess {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 #1a2a22, stop:1 #141e1a);
    border: 1px solid #166534;
    border-radius: 10px;
    padding: 14px;
}

QFrame#StatCardSuccess:hover {
    border: 1px solid #22c55e;
}

QFrame#StatCardML {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 #2a1a2e, stop:1 #1e1424);
    border: 1px solid #6d28d9;
    border-radius: 10px;
    padding: 14px;
}

QFrame#StatCardML:hover {
    border: 1px solid #8b5cf6;
}

/* ============ LABELS ============ */
QLabel#CardTitle {
    font-size: 11px;
    font-weight: 600;
    color: #9ca3af;
    letter-spacing: 0.5px;
}

QLabel#CardValue {
    font-size: 28px;
    font-weight: 700;
    color: #f1f5f9;
}

QLabel#CardValueBig {
    font-size: 36px;
    font-weight: 700;
    color: #f1f5f9;
}

QLabel#CardPercent {
    font-size: 12px;
    color: #64748b;
}

QLabel#SectionLabel {
    font-size: 12px;
    font-weight: 600;
    color: #9ca3af;
    padding: 8px 0;
}

QLabel#StatusRunning {
    font-weight: 600;
    color: #22c55e;
    padding: 6px 12px;
    background: rgba(34, 197, 94, 0.15);
    border-radius: 6px;
}

QLabel#StatusStopped {
    font-weight: 600;
    color: #ef4444;
    padding: 6px 12px;
    background: rgba(239, 68, 68, 0.15);
    border-radius: 6px;
}

/* ============ COMBOBOX ============ */
QComboBox {
    background: #1a1f2e;
    border: 1px solid #374151;
    border-radius: 6px;
    padding: 8px 12px;
    min-width: 140px;
    color: #e5e7eb;
}

QComboBox:hover {
    border-color: #3b82f6;
}

QComboBox::drop-down {
    border: none;
    width: 30px;
}

QComboBox::down-arrow {
    image: none;
    border-left: 5px solid transparent;
    border-right: 5px solid transparent;
    border-top: 6px solid #9ca3af;
    margin-right: 10px;
}

QComboBox QAbstractItemView {
    background: #1a1f2e;
    border: 1px solid #374151;
    selection-background-color: #3b82f6;
}

/* ============ BUTTONS ============ */
QPushButton {
    font-weight: 600;
    padding: 8px 16px;
    border-radius: 6px;
    border: none;
}

QPushButton#StartBtn {
    background: #22c55e;
    color: white;
}

QPushButton#StartBtn:hover {
    background: #16a34a;
}

QPushButton#StartBtn:disabled {
    background: #374151;
    color: #6b7280;
}

QPushButton#StopBtn {
    background: #ef4444;
    color: white;
}

QPushButton#StopBtn:hover {
    background: #dc2626;
}

QPushButton#StopBtn:disabled {
    background: #374151;
    color: #6b7280;
}

/* ============ TABLE ============ */
QTableWidget {
    background: #111827;
    border: 1px solid #1f2937;
    border-radius: 8px;
    gridline-color: #1f2937;
    selection-background-color: rgba(59, 130, 246, 0.3);
}

QTableWidget::item {
    padding: 10px 14px;
    border-bottom: 1px solid #1f2937;
}

QTableWidget::item:selected {
    background: rgba(59, 130, 246, 0.2);
}

QHeaderView::section {
    background: #0d1117;
    color: #6b7280;
    font-weight: 600;
    font-size: 11px;
    text-transform: uppercase;
    padding: 12px 14px;
    border: none;
    border-bottom: 1px solid #1f2937;
}

QTableWidget QScrollBar:vertical {
    background: #111827;
    width: 8px;
}

QTableWidget QScrollBar::handle:vertical {
    background: #374151;
    border-radius: 4px;
}

/* ============ LOG VIEW ============ */
QPlainTextEdit {
    background: #0d1117;
    border: 1px solid #1f2937;
    border-radius: 8px;
    padding: 10px;
    font-family: 'Consolas', monospace;
    font-size: 11px;
    color: #9ca3af;
}

QPlainTextEdit QScrollBar:vertical {
    background: #0d1117;
    width: 8px;
}

QPlainTextEdit QScrollBar::handle:vertical {
    background: #374151;
    border-radius: 4px;
}


/* ============ STATS SECTION ============ */
QFrame#StatBox {
    background: #111827;
    border: 1px solid #1f2937;
    border-radius: 8px;
    padding: 10px;
}

QLabel#StatTitle {
    font-size: 14px;
    font-weight: 700;
    color: #f1f5f9;
    margin-bottom: 5px;
}

QListWidget#IPList {
    background: transparent;
    border: none;
    color: #e5e7eb;
}

QListWidget#IPList::item {
    padding: 8px;
    border-bottom: 1px solid #1f2937;
}

QLabel#IPBadge {
    background: #ef4444;
    color: white;
    font-size: 10px;
    font-weight: 700;
    padding: 2px 6px;
    border-radius: 4px;
}

/* ============ SCROLLBARS ============ */
QScrollBar:vertical {
    background: #0f1419;
    width: 10px;
}

QScrollBar::handle:vertical {
    background: #374151;
    border-radius: 5px;
    min-height: 30px;
}

QScrollBar::handle:vertical:hover {
    background: #4b5563;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}
"""


# =====================================================================
#   Signals
# =====================================================================
class AlertSignals(QtCore.QObject):
    new_alert = Signal(dict)
    stats_changed = Signal(dict)
    log_message = Signal(str)
    refresh_map = Signal()


# =====================================================================
#   MODERN SIEM WINDOW
# =====================================================================
class ModernSIEM(QtWidgets.QMainWindow):

    def __init__(self):
        super().__init__()
        self.setWindowTitle("SIEM Dashboard")
        self.resize(1100, 750)
        self.setMinimumSize(800, 500)

        self.setStyleSheet(DARK_STYLESHEET)

        self.alert_manager = AlertManager()
        self.signals = AlertSignals()

        self.stats = {
            "SQL Injection": 0,
            "XSS": 0,
            "Brute Force": 0,
            "ML Anomaly": 0,
            "Malicious IP": 0,
            "Others": 0,
            "Total": 0
        }
        
        self.country_counts = {}
        self.ip_counts = {}

        # ML Detector avec chemin absolu
        base_dir = os.path.dirname(os.path.abspath(__file__))
        model_path = os.path.join(base_dir, 'ml', 'anomaly_model.pkl')
        self.ml_detector = AnomalyDetector(model_path=model_path)
        self.ml_scores = []  # Store recent ML scores for average

        self.all_alerts = []
        self.alert_coords = [] # Liste des coordonnées pour la map

        self.build_ui()

        self.signals.new_alert.connect(self.add_alert_to_table)
        self.signals.stats_changed.connect(self.update_stats_cards)
        self.signals.log_message.connect(self.append_log)
        self.signals.refresh_map.connect(self.update_map)
        
        self.attack_generator = AttackGenerator(sleep_interval=2)

        self.start_watcher()

    # -----------------------------------------------------------
    #   UI
    # -----------------------------------------------------------
    def build_ui(self):
        # Scroll Area for the whole page
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setCentralWidget(scroll)

        # Main container inside scroll
        container = QtWidgets.QWidget()
        scroll.setWidget(container)

        layout = QtWidgets.QVBoxLayout(container)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)

        # ============ HEADER =============
        header = QtWidgets.QHBoxLayout()
        
        title_label = QtWidgets.QLabel("SIEM Dashboard")
        title_label.setStyleSheet("""
            font-size: 22px;
            font-weight: 700;
            color: #f1f5f9;
        """)
        header.addWidget(title_label)
        header.addStretch()
        
        self.live_indicator = QtWidgets.QLabel("LIVE")
        self.live_indicator.setStyleSheet("""
            font-size: 12px;
            font-weight: 600;
            color: #22c55e;
            padding: 5px 12px;
            background: rgba(34, 197, 94, 0.15);
            border-radius: 12px;
        """)
        header.addWidget(self.live_indicator)
        
        layout.addLayout(header)

        # ============ STAT CARDS =============
        cards = QtWidgets.QHBoxLayout()
        cards.setSpacing(12)
        layout.addLayout(cards)

        self.card_sqli = self.create_card("SQL Injection", "danger")
        self.card_xss = self.create_card("XSS", "normal")
        self.card_bruteforce = self.create_card("Brute Force", "normal")
        self.card_ml = self.create_card("ML Anomaly", "ml")
        self.card_total = self.create_card("Total", "success", big=True)

        cards.addWidget(self.card_sqli)
        cards.addWidget(self.card_xss)
        cards.addWidget(self.card_bruteforce)
        cards.addWidget(self.card_ml)
        cards.addWidget(self.card_total)

        # ============ CONTROL BAR =============
        control_layout = QtWidgets.QHBoxLayout()
        control_layout.setSpacing(10)
        layout.addLayout(control_layout)

        filter_label = QtWidgets.QLabel("Filtre:")
        filter_label.setStyleSheet("color: #6b7280;")
        control_layout.addWidget(filter_label)

        self.filter_box = QtWidgets.QComboBox()
        self.filter_box.addItems(["Toutes", "SQL Injection", "XSS", "Brute Force", "ML Anomaly", "Malicious IP", "CSRF", "File Upload", "OS Injection", "CRLF"])
        self.filter_box.currentTextChanged.connect(self.apply_filter)
        control_layout.addWidget(self.filter_box)
        
        control_layout.addStretch()
        
        self.generator_status_label = QtWidgets.QLabel("Arrêté")
        self.generator_status_label.setObjectName("StatusStopped")
        control_layout.addWidget(self.generator_status_label)
        
        self.start_generator_btn = QtWidgets.QPushButton("Démarrer")
        self.start_generator_btn.setObjectName("StartBtn")
        self.start_generator_btn.setCursor(Qt.PointingHandCursor)
        self.start_generator_btn.clicked.connect(self.start_attack_generator)
        control_layout.addWidget(self.start_generator_btn)
        
        self.stop_generator_btn = QtWidgets.QPushButton("Arrêter")
        self.stop_generator_btn.setObjectName("StopBtn")
        self.stop_generator_btn.setCursor(Qt.PointingHandCursor)
        self.stop_generator_btn.clicked.connect(self.stop_attack_generator)
        self.stop_generator_btn.setEnabled(False)
        control_layout.addWidget(self.stop_generator_btn)

        # ============ NEW STATS SECTION (PIE & IPs) =============
        stats_layout = QtWidgets.QHBoxLayout()
        stats_layout.setSpacing(16)
        layout.addLayout(stats_layout)

        # Col 1: Top 5 Pays
        self.country_frame = QtWidgets.QFrame()
        self.country_frame.setObjectName("StatBox")
        self.country_frame.setMinimumHeight(350)
        country_vbox = QtWidgets.QVBoxLayout(self.country_frame)
        
        country_title = QtWidgets.QLabel("TOP 5 PAYS ATTAQUANTS")
        country_title.setObjectName("StatTitle")
        country_vbox.addWidget(country_title)

        self.pie_series = QPieSeries()
        self.chart = QChart()
        self.chart.addSeries(self.pie_series)
        self.chart.setMargins(QtCore.QMargins(0, 0, 0, 0))
        self.chart.setBackgroundVisible(False)
        self.chart.legend().setVisible(True)
        self.chart.legend().setAlignment(Qt.AlignRight)
        self.chart.legend().setLabelColor(QtGui.QColor("#9ca3af"))

        self.chart_view = QChartView(self.chart)
        self.chart_view.setRenderHint(QtGui.QPainter.Antialiasing)
        self.chart_view.setStyleSheet("background: transparent;")
        country_vbox.addWidget(self.chart_view)
        
        stats_layout.addWidget(self.country_frame, 1)

        # Col 2: Top 10 IPs
        self.ip_frame = QtWidgets.QFrame()
        self.ip_frame.setObjectName("StatBox")
        self.ip_frame.setMinimumHeight(300)
        ip_vbox = QtWidgets.QVBoxLayout(self.ip_frame)

        ip_title = QtWidgets.QLabel("TOP 10 IPS ATTAQUANTES")
        ip_title.setObjectName("StatTitle")
        ip_vbox.addWidget(ip_title)

        self.ip_list_widget = QtWidgets.QListWidget()
        self.ip_list_widget.setObjectName("IPList")
        ip_vbox.addWidget(self.ip_list_widget)

        stats_layout.addWidget(self.ip_frame, 1)

        # ============ ALERTS SECTION =============
        alerts_header = QtWidgets.QLabel("Alertes récentes")
        alerts_header.setObjectName("SectionLabel")
        layout.addWidget(alerts_header)

        self.table = QtWidgets.QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["Timestamp", "Type", "Score ML", "Pays", "Ville", "Pattern"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QtWidgets.QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QtWidgets.QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QtWidgets.QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(4, QtWidgets.QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(5, QtWidgets.QHeaderView.Stretch)
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.table.setShowGrid(False)
        self.table.verticalHeader().setVisible(False)
        self.table.setMinimumHeight(300)
        layout.addWidget(self.table)

        # ============ WORLD MAP SECTION =============
        map_label = QtWidgets.QLabel("Carte des Menaces")
        map_label.setObjectName("SectionLabel")
        layout.addWidget(map_label)

        self.web_view = QWebEngineView()
        self.web_view.setMinimumHeight(400)
        layout.addWidget(self.web_view)
        self.update_map() # Initial map

        # ============ LIVE LOG VIEW =============
        log_header = QtWidgets.QLabel("Logs")
        log_header.setObjectName("SectionLabel")
        layout.addWidget(log_header)
        
        self.log_view = QtWidgets.QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setMinimumHeight(120)
        self.log_view.setMaximumHeight(150)
        self.log_view.setPlaceholderText("En attente...")
        layout.addWidget(self.log_view)

        # Add some bottom spacing
        layout.addSpacing(20)

    # -----------------------------------------------------------
    #   CARD TEMPLATE
    # -----------------------------------------------------------
    def create_card(self, title, variant="normal", big=False):
        frame = QtWidgets.QFrame()
        
        if variant == "danger":
            frame.setObjectName("StatCardDanger")
        elif variant == "success":
            frame.setObjectName("StatCardSuccess")
        elif variant == "ml":
            frame.setObjectName("StatCardML")
        else:
            frame.setObjectName("StatCard")
        
        layout = QtWidgets.QVBoxLayout(frame)
        layout.setSpacing(6)
        layout.setContentsMargins(16, 14, 16, 14)

        title_label = QtWidgets.QLabel(title.upper())
        title_label.setObjectName("CardTitle")
        layout.addWidget(title_label)

        count_label = QtWidgets.QLabel("0")
        count_label.setObjectName("CardValueBig" if big else "CardValue")
        layout.addWidget(count_label)

        pct_label = QtWidgets.QLabel("0%")
        pct_label.setObjectName("CardPercent")
        layout.addWidget(pct_label)

        frame._count = count_label
        frame._pct = pct_label
        return frame

    # -----------------------------------------------------------
    #   UPDATE CARDS
    # -----------------------------------------------------------
    @Slot(dict)
    def update_stats_cards(self, stats):
        total = max(stats.get("Total", 0), 1)

        def update(card, value):
            pct = round((value / total) * 100)
            card._count.setText(str(value))
            card._pct.setText(f"{pct}%")

        # Unification des clés pour supporter les variantes de casse
        sqli = stats.get("SQL Injection", 0)
        xss = stats.get("XSS", 0) + stats.get("XSS injection", 0)
        brute = stats.get("Brute Force", 0)
        ml = stats.get("ML Anomaly", 0)

        update(self.card_sqli, sqli)
        update(self.card_xss, xss)
        update(self.card_bruteforce, brute)
        update(self.card_ml, ml)

        self.card_total._count.setText(str(stats.get("Total", 0)))
        self.card_total._pct.setText("total")

    # -----------------------------------------------------------
    #   TABLE ALERT
    # -----------------------------------------------------------
    @Slot(dict)
    def add_alert_to_table(self, alert):
        self.all_alerts.append(alert)
        
        # Update Country stats
        country = alert.get("country", "Unknown")
        self.country_counts[country] = self.country_counts.get(country, 0) + 1
        self.update_country_chart()

        # Update IP stats
        parts = alert["line"].split()
        ip_addr = parts[1] if len(parts) > 1 else "127.0.0.1"
        
        if ip_addr != "127.0.0.1":
            self.ip_counts[ip_addr] = self.ip_counts.get(ip_addr, 0) + 1
            self.update_ip_list()

        self.apply_filter()
        # Scroll to last row (newest alert)
        if self.table.rowCount() > 0:
            self.table.scrollToBottom()

    def update_country_chart(self):
        self.pie_series.clear()
        self.pie_series.setPieSize(0.65) # Laisse de la place pour les labels externes
        # Sort and take top 5
        sorted_countries = sorted(self.country_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        
        colors = ["#ef4444", "#3b82f6", "#10b981", "#f59e0b", "#8b5cf6"]
        
        for i, (country, count) in enumerate(sorted_countries):
            slice = self.pie_series.append(f"{country} ({count})", count)
            if i < len(colors):
                slice.setBrush(QtGui.QColor(colors[i]))
            slice.setLabelVisible(True)
            slice.setLabelPosition(QPieSlice.LabelOutside)
            slice.setLabelColor(QtGui.QColor("#f1f5f9"))

    def update_ip_list(self):
        self.ip_list_widget.clear()
        # Sort and take top 10
        sorted_ips = sorted(self.ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]

        for ip, count in sorted_ips:
            item = QtWidgets.QListWidgetItem()
            item.setSizeHint(QtCore.QSize(0, 45))  # Fixe la hauteur pour éviter l'écrasement
            self.ip_list_widget.addItem(item)
            
            # Custom widget for the list item
            widget = QtWidgets.QWidget()
            h_layout = QtWidgets.QHBoxLayout(widget)
            h_layout.setContentsMargins(12, 0, 12, 0)
            
            ip_label = QtWidgets.QLabel(ip)
            ip_label.setStyleSheet("font-weight: 700; color: #ffffff; font-size: 14px;")
            
            count_label = QtWidgets.QLabel(f"{count} attaques")
            count_label.setStyleSheet("color: #94a3b8; font-size: 12px; font-weight: 600;")
            
            badge = QtWidgets.QLabel("DANGER")
            badge.setStyleSheet("""
                background-color: #ef4444;
                color: white;
                font-size: 10px;
                font-weight: 800;
                padding: 3px 8px;
                border-radius: 4px;
            """)
            
            h_layout.addWidget(ip_label)
            h_layout.addStretch()
            h_layout.addWidget(count_label)
            h_layout.addSpacing(15)
            h_layout.addWidget(badge)
            
            self.ip_list_widget.setItemWidget(item, widget)

    def apply_filter(self):
        selected = self.filter_box.currentText()
        self.table.setRowCount(0)

        for a in self.all_alerts:
            if selected != "Toutes" and a["type"] != selected:
                continue

            row = self.table.rowCount()
            self.table.insertRow(row)

            ts_item = QtWidgets.QTableWidgetItem(a["timestamp"])
            ts_item.setForeground(QtGui.QColor("#9ca3af"))
            self.table.setItem(row, 0, ts_item)
            
            type_item = QtWidgets.QTableWidgetItem(a["type"])
            if a["type"] == "SQL Injection":
                type_item.setForeground(QtGui.QColor("#ef4444"))
            elif a["type"] == "XSS":
                type_item.setForeground(QtGui.QColor("#f59e0b"))
            elif a["type"] == "Brute Force":
                type_item.setForeground(QtGui.QColor("#3b82f6"))
            elif a["type"] == "ML Anomaly":
                type_item.setForeground(QtGui.QColor("#8b5cf6"))
            elif a["type"] == "Malicious IP":
                type_item.setForeground(QtGui.QColor("#ec4899"))  # Rose/Pink pour IP malveillante
            else:
                type_item.setForeground(QtGui.QColor("#6b7280"))
            self.table.setItem(row, 1, type_item)
            
            # Score ML avec couleur
            ml_score = a.get("ml_score", 0)
            score_text = f"{int(ml_score * 100)}%"
            score_item = QtWidgets.QTableWidgetItem(score_text)
            if ml_score >= 0.7:
                score_item.setForeground(QtGui.QColor("#ef4444"))  # Rouge
            elif ml_score >= 0.4:
                score_item.setForeground(QtGui.QColor("#f59e0b"))  # Orange
            else:
                score_item.setForeground(QtGui.QColor("#22c55e"))  # Vert
            self.table.setItem(row, 2, score_item)
            
            # Pays
            country = a.get("country", "-")
            country_item = QtWidgets.QTableWidgetItem(country)
            country_item.setForeground(QtGui.QColor("#e5e7eb"))
            self.table.setItem(row, 3, country_item)
            
            # Ville
            city = a.get("city", "-")
            if city == "Unknown": city = "-"
            city_item = QtWidgets.QTableWidgetItem(city)
            city_item.setForeground(QtGui.QColor("#9ca3af"))
            self.table.setItem(row, 4, city_item)
            
            pattern_item = QtWidgets.QTableWidgetItem(a["pattern"])
            pattern_item.setForeground(QtGui.QColor("#fbbf24"))
            self.table.setItem(row, 5, pattern_item)

    # -----------------------------------------------------------
    #   MAP UPDATE
    # -----------------------------------------------------------
    @Slot()
    def update_map(self):
        """Met à jour la carte avec les marqueurs d'alertes."""
        try:
            m = folium.Map(
                location=[20, 0], 
                zoom_start=2, 
                tiles="CartoDB dark_matter",
                no_wrap=True,
                min_zoom=2
            )
            
            for coord in self.alert_coords:
                if coord != [0, 0]:
                    folium.CircleMarker(
                        location=coord,
                        radius=6,
                        color="#ef4444",
                        weight=2,
                        fill=True,
                        fill_color="#ef4444",
                        fill_opacity=0.7
                    ).add_to(m)

            data = io.BytesIO()
            m.save(data, close_file=False)
            html_content = data.getvalue().decode()
            self.web_view.setHtml(html_content)
            print(f"[MAP] Mise à jour effectuée avec {len(self.alert_coords)} marqueurs")
        except Exception as e:
            print(f"[MAP ERROR] {e}")

    # -----------------------------------------------------------
    #   LOG APPEND
    # -----------------------------------------------------------
    @Slot(str)
    def append_log(self, text):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_view.appendPlainText(f"[{timestamp}] {text}")
        scrollbar = self.log_view.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    # -----------------------------------------------------------
    #   WATCH LOG FILE
    # -----------------------------------------------------------
    def start_watcher(self):
        thread = threading.Thread(target=self.watcher_loop, daemon=True)
        thread.start()

    def watcher_loop(self):
        # Chemin absolu pour le fichier chiffré
        base_dir = os.path.dirname(os.path.abspath(__file__))
        log_path = settings.CHIFFRED_PATH or "chiffred.enc"
        
        # Si le chemin n'est pas absolu, le rendre relatif au dossier du projet
        if not os.path.isabs(log_path):
            log_path = os.path.join(base_dir, log_path)
        
        last_pos = 0
        last_size = 0
        
        self.signals.log_message.emit(f"[SYSTEM] Surveillance: {log_path}")

        while True:
            try:
                if not os.path.exists(log_path):
                    time.sleep(1)
                    continue
                
                # Vérifier si le fichier a changé
                current_size = os.path.getsize(log_path)
                
                # Si le fichier a été tronqué/réinitialisé, recommencer du début
                if current_size < last_size:
                    last_pos = 0
                    self.signals.log_message.emit("[SYSTEM] Fichier réinitialisé, relecture...")
                
                last_size = current_size

                with open(log_path, "rb") as f:
                    f.seek(last_pos)
                    for line in f:
                        if not line.strip(): 
                            continue
                        
                        # Importer ici pour éviter les problèmes de cache
                        from utils.dechiffrer import dechiffrer_donnees
                        
                        try:
                            log_line = dechiffrer_donnees(line)
                            
                            if not log_line:
                                # Log brut si déchiffrement échoue
                                self.signals.log_message.emit(f"[CRYPTO] Echec déchiffrement")
                                continue
                            
                            stripped = log_line.strip()
                            
                            # Calculer le score ML pour ce log
                            ml_score = 0.0
                            ml_is_anomaly = False
                            if self.ml_detector.is_trained:
                                ml_is_anomaly, ml_score = self.ml_detector.predict(log_line)
                            
                            # Afficher le log déchiffré + Score ML
                            ml_text = f" [ML:{ml_score:.2f}]"
                            self.signals.log_message.emit(stripped + ml_text)
                            # Extraction de l'IP (TIMESTAMP IP METHOD ...)
                            parts = stripped.split()
                            ip_addr = parts[1] if len(parts) > 1 else "127.0.0.1"

                            # Geolocation (une seule fois par ligne)
                            geo_info = get_ip_info(ip_addr)
                            city_str = f" ({geo_info['city']})" if geo_info['city'] != "Unknown" else ""

                            # Analyse avec les détecteurs
                            attack_found = False
                            attack_type = ""
                            pattern = ""
                            
                            for detect in DETECTORS:
                                # Optimisation: On ne vérifie l'IP via l'API que si le trafic semble 
                                # un minimum suspect (ou si c'est un détecteur local gratuit)
                                if detect == detect_ip_reputation:
                                    if not ml_is_anomaly and ml_score < 0.02:
                                        continue  # Skip AbuseIPDB pour le trafic extrêmement propre
                                
                                found, details, a_type = detect(log_line)
                                if found:
                                    attack_found = True
                                    attack_type = a_type
                                    pattern = str(details[0]) if details else "Pattern inconnu"
                                    break
                            
                            # Si attaque détectée ou anomalie ML forte (> 0.60)
                            if attack_found or (ml_is_anomaly and ml_score > 0.60):
                                alert = {
                                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                    "type": attack_type if attack_found else "ML Anomaly",
                                    "pattern": pattern if attack_found else f"Score: {ml_score:.2f}",
                                    "line": stripped,
                                    "ml_score": ml_score,
                                    "country": geo_info["country"],
                                    "city": geo_info["city"]
                                }
                                
                                if attack_found:
                                    self.alert_manager.log_alert(attack_type, pattern, log_line)
                                    if attack_type in self.stats: self.stats[attack_type] += 1
                                    else: self.stats["Others"] += 1
                                else:
                                    self.alert_manager.log_alert("ML Anomaly", f"score:{ml_score:.2f}", log_line)
                                    self.stats["ML Anomaly"] += 1
                                    
                                self.stats["Total"] += 1
                                
                                # Mise à jour coordonnées pour la carte
                                if geo_info["coords"] != [0, 0]:
                                    self.alert_coords.append(geo_info["coords"])
                                    self.signals.refresh_map.emit()
                                
                                self.signals.new_alert.emit(alert)
                                self.signals.stats_changed.emit(self.stats)
                                
                                print(f"[GEO] Alerte: {alert['type']} depuis {geo_info['country']}{city_str} ({ip_addr}) bloquée")
                                    
                        except Exception as e:
                            print(f"[Watcher] Erreur déchiffrement: {e}")

                    last_pos = f.tell()

                time.sleep(settings.SLEEP_INTERVAL)

            except Exception as e:
                print(f"[Watcher] Erreur globale: {e}")
                time.sleep(1)
    
    # -----------------------------------------------------------
    #   ATTACK GENERATOR CONTROLS
    # -----------------------------------------------------------
    def start_attack_generator(self):
        self.attack_generator.start()
        self.generator_status_label.setText("Actif")
        self.generator_status_label.setObjectName("StatusRunning")
        self.generator_status_label.setStyle(self.generator_status_label.style())
        self.start_generator_btn.setEnabled(False)
        self.stop_generator_btn.setEnabled(True)
        self.signals.log_message.emit("[SYSTEM] Générateur démarré")
    
    def stop_attack_generator(self):
        self.attack_generator.stop()
        self.generator_status_label.setText("Arrêté")
        self.generator_status_label.setObjectName("StatusStopped")
        self.generator_status_label.setStyle(self.generator_status_label.style())
        self.start_generator_btn.setEnabled(True)
        self.stop_generator_btn.setEnabled(False)
        self.signals.log_message.emit("[SYSTEM] Générateur arrêté")
    
    def closeEvent(self, event):
        if self.attack_generator.is_running():
            self.attack_generator.stop()
        
        # Fermer proprement le reader de geo_finder
        from geo_finder import close_reader
        close_reader()
        
        event.accept()


# =====================================================================
#   RUN
# =====================================================================
def run_app():
    app = QtWidgets.QApplication(sys.argv)
    font = QtGui.QFont("Segoe UI", 10)
    app.setFont(font)
    window = ModernSIEM()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    run_app()
