"""
Main Application Window
Primary GUI interface
"""

import json
import os
from datetime import datetime

from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLineEdit, QPushButton, QTextEdit, QLabel,
    QProgressBar, QMessageBox, QListWidget, QSizePolicy
)

from PyQt5.QtCore import QThread, pyqtSignal


# Import core modules
from core.url_analyzer import URLAnalyzer
from core.domain_info import DomainInfo
from core.ssl_checker import SSLChecker
from core.heuristics import HeuristicAnalyzer
from core.scoring_engine import ScoringEngine
from core.reputation_checker import ReputationChecker


# =====================================================
# ANALYSIS THREAD
# =====================================================

class AnalysisThread(QThread):

    finished = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, url, settings):
        super().__init__()

        self.url = url
        self.settings = settings


    def run(self):

        try:
            url_analyzer = URLAnalyzer()
            domain_info = DomainInfo()
            ssl_checker = SSLChecker()
            heuristic = HeuristicAnalyzer()
            scoring = ScoringEngine()

            vt_key = self.settings.get("api_keys", {}).get("virustotal", "")
            otx_key = self.settings.get("api_keys", {}).get("otx", "")

            reputation = ReputationChecker(vt_key, otx_key)

            # Step 1: URL
            url_data = url_analyzer.analyze_url(self.url)
            domain = url_data["domain"]

            # Step 2: Domain info
            whois = domain_info.get_whois_info(domain)
            dns = domain_info.get_dns_records(domain)

            # Step 3: SSL
            ssl = ssl_checker.check_ssl_certificate(domain)

            # Step 4: Heuristics
            heuristics = heuristic.analyze_heuristics(self.url, domain)

            # Step 5: Reputation
            rep = reputation.check_all_reputation(self.url)

            results = {
                "url_analysis": url_data,
                "whois_info": whois,
                "dns_info": dns,
                "ssl_info": ssl,
                "heuristics": heuristics,
                "reputation": rep
            }

            # Step 6: Score
            risk = scoring.calculate_risk_score(results)
            results["risk_assessment"] = risk

            self.finished.emit(results)

        except Exception as e:
            self.error.emit(str(e))


# =====================================================
# MAIN WINDOW
# =====================================================

class MainWindow(QMainWindow):

    def __init__(self, settings=None):
        super().__init__()

        self.settings = settings or {}
        self.current_results = None

        self.init_ui()


    # =================================================
    # UI SETUP
    # =================================================

    def init_ui(self):

        self.setWindowTitle("Scam Advisor - Website Trust Analyzer")
        self.setGeometry(100, 100, 1200, 800)


        # Central Widget
        central = QWidget()
        self.setCentralWidget(central)

        main_layout = QHBoxLayout()
        central.setLayout(main_layout)


        # ---------------- LEFT PANEL ----------------

        left_panel = QWidget()
        left_layout = QVBoxLayout()
        left_panel.setLayout(left_layout)
        left_panel.setMaximumWidth(300)

        history_label = QLabel("📜 Search History")
        history_label.setStyleSheet("font-size:16px;font-weight:bold;")

        self.history_list = QListWidget()
        self.history_list.itemClicked.connect(self.load_history_item)

        clear_btn = QPushButton("🗑 Clear History")
        clear_btn.clicked.connect(self.clear_history)

        left_layout.addWidget(history_label)
        left_layout.addWidget(self.history_list)
        left_layout.addWidget(clear_btn)


        # ---------------- RIGHT PANEL ----------------

        right_panel = QWidget()
        right_layout = QVBoxLayout()
        right_panel.setLayout(right_layout)


        # URL Input

        url_layout = QHBoxLayout()

        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("Enter website URL...")
        self.url_input.returnPressed.connect(self.start_analysis)

        self.analyze_btn = QPushButton("🔍 Analyze")
        self.analyze_btn.clicked.connect(self.start_analysis)

        self.save_btn = QPushButton("💾 Save")
        self.save_btn.clicked.connect(self.save_current_search)
        self.save_btn.setEnabled(False)

        url_layout.addWidget(QLabel("Website:"))
        url_layout.addWidget(self.url_input, 1)
        url_layout.addWidget(self.analyze_btn)
        url_layout.addWidget(self.save_btn)


        # Progress Bar

        self.progress = QProgressBar()
        self.progress.setVisible(False)


        # Results Box

        self.results = QTextEdit()
        self.results.setReadOnly(True)

        self.results.setSizePolicy(
            QSizePolicy.Expanding,
            QSizePolicy.Expanding
        )


        # Layout Add

        right_layout.addLayout(url_layout)
        right_layout.addWidget(self.progress)
        right_layout.addWidget(self.results)

        main_layout.addWidget(left_panel, 1)
        main_layout.addWidget(right_panel, 3)


        # Load history
        self.load_history()


    # =================================================
    # HISTORY
    # =================================================

    def load_history(self):

        try:
            file = os.path.join("data", "history.json")

            if not os.path.exists(file):
                return

            with open(file, "r") as f:
                data = json.load(f)

            for item in data:
                self.history_list.addItem(
                    f"{item['url']} - {item['risk_level']}"
                )

        except Exception as e:
            print("History error:", e)


    def save_current_search(self):

        if not self.current_results:
            return

        try:
            os.makedirs("data", exist_ok=True)

            file = os.path.join("data", "history.json")

            data = []

            if os.path.exists(file):
                with open(file, "r") as f:
                    data = json.load(f)

            entry = {
                "url": self.current_results["url_analysis"]["normalized_url"],
                "risk_level": self.current_results["risk_assessment"]["risk_level"],
                "score": self.current_results["risk_assessment"]["overall_score"],
                "time": datetime.now().isoformat()
            }

            data = [i for i in data if i["url"] != entry["url"]]
            data.insert(0, entry)
            data = data[:50]

            with open(file, "w") as f:
                json.dump(data, f, indent=2)

            self.history_list.clear()

            for item in data:
                self.history_list.addItem(
                    f"{item['url']} - {item['risk_level']}"
                )

            QMessageBox.information(self, "Saved", "Saved successfully!")

        except Exception as e:
            QMessageBox.warning(self, "Error", str(e))


    def load_history_item(self, item):

        url = item.text().split(" - ")[0]
        self.url_input.setText(url)


    def clear_history(self):

        reply = QMessageBox.question(
            self,
            "Clear History",
            "Delete all history?",
            QMessageBox.Yes | QMessageBox.No
        )

        if reply == QMessageBox.Yes:

            try:
                file = os.path.join("data", "history.json")

                if os.path.exists(file):
                    os.remove(file)

                self.history_list.clear()

            except Exception as e:
                QMessageBox.warning(self, "Error", str(e))


    # =================================================
    # ANALYSIS
    # =================================================

    def start_analysis(self):

        url = self.url_input.text().strip()

        if not url:
            QMessageBox.warning(self, "Error", "Enter URL first")
            return

        self.analyze_btn.setEnabled(False)
        self.save_btn.setEnabled(False)

        self.progress.setVisible(True)
        self.progress.setRange(0, 0)

        self.thread = AnalysisThread(url, self.settings)

        self.thread.finished.connect(self.on_complete)
        self.thread.error.connect(self.on_analysis_error)

        self.thread.start()


    def on_complete(self, results):

        self.analyze_btn.setEnabled(True)
        self.save_btn.setEnabled(True)

        self.progress.setVisible(False)

        self.current_results = results

        self.display_results(results)


    def on_analysis_error(self, msg):
        """Handle analysis errors"""

        print("ANALYSIS ERROR:", msg)

        QMessageBox.critical(
            self,
            "Analysis Error",
            f"Something went wrong:\n\n{msg}"
        )


    # =================================================
    # RESULTS
    # =================================================

    def display_results(self, results):

        risk = results["risk_assessment"]
        score = risk["overall_score"]


        # Status

        if score >= 70:
            emoji = "✅🟢"
            status = "SAFE"
            color = "#00ff00"

        elif score >= 40:
            emoji = "⚠️🟡"
            status = "SUSPICIOUS"
            color = "#ffcc00"

        else:
            emoji = "❌🔴"
            status = "PHISHING"
            color = "#ff4444"


        self.results.setStyleSheet(f"color:{color};font-size:15px;")


        output = f"""
🛡️ SCAM ADVISOR REPORT

Website: {results['url_analysis']['normalized_url']}

Status: {emoji} {status}
Score: {score}/100


RISK FACTORS:
"""

        for f in risk["risk_factors"]:
            output += f"• {f}\n"


        rep = results.get("reputation", {})

        output += "\nREPUTATION:\n"

        vt = rep.get("virustotal", {})
        otx = rep.get("alienvault_otx", {})

        if "detection_ratio" in vt:
            output += f"• VirusTotal: {vt['detection_ratio']}\n"
        else:
            output += "• VirusTotal: No data\n"

        if "pulse_count" in otx:
            output += f"• AlienVault: {otx['pulse_count']} pulses\n"
        else:
            output += "• AlienVault: No data\n"


        output += f"""

DETAILS:
- Domain: {results['url_analysis']['domain']}
- HTTPS: {'Yes' if results['url_analysis']['is_https'] else 'No'}
- Heuristic Score: {results['heuristics']['heuristic_score']}/100
"""

        self.results.setPlainText(output)
