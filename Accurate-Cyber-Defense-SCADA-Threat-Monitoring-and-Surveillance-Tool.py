import sys
import socket
import threading
import time
import json
import datetime
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import numpy as np
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QTextEdit, QLineEdit, QPushButton, 
                             QLabel, QTabWidget, QAction, QMenu, QMenuBar,
                             QStatusBar, QSplitter, QFrame, QGridLayout,
                             QListWidget, QMessageBox, QFileDialog, QInputDialog,
                             QTableWidget, QTableWidgetItem, QHeaderView)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QFont, QPalette, QColor, QIcon
import scapy.all as scapy
import requests
import pandas as pd
from collections import deque
import subprocess
import re
import os

class MplCanvas(FigureCanvas):
    def __init__(self, parent=None, width=5, height=4, dpi=100):
        fig = Figure(figsize=(width, height), dpi=dpi)
        self.axes = fig.add_subplot(111)
        super(MplCanvas, self).__init__(fig)

class RealTimePlot(MplCanvas):
    def __init__(self, *args, **kwargs):
        super(RealTimePlot, self).__init__(*args, **kwargs)
        self.xdata = deque(maxlen=50)
        self.ydata = deque(maxlen=50)
        self._plot_ref = None
        self.update_plot()
        
    def update_plot(self):
        if self._plot_ref is None:
            plot_refs = self.axes.plot(self.xdata, self.ydata, 'r')
            self._plot_ref = plot_refs[0]
        else:
            self._plot_ref.set_data(self.xdata, self.ydata)
            
        self.axes.relim()
        self.axes.autoscale_view()
        self.draw()

class CyberSecurityTool(QMainWindow):
    update_signal = pyqtSignal(str)
    telegram_signal = pyqtSignal(str, str)
    
    def __init__(self):
        super().__init__()
        self.monitoring_ips = {}
        self.telegram_token = None
        self.telegram_chat_id = None
        self.command_history = []
        self.history_index = -1
        self.packet_count = 0
        self.threat_count = 0
        self.microwave_interception_count = 0
        self.initUI()
        self.setup_connections()
        self.load_config()
        
    def initUI(self):
        self.setWindowTitle("Accurate Cyber Defense SCADA Threat Monitor and surveillance Tool")
        self.setGeometry(100, 100, 1400, 900)
        
        # Apply green and black theme
        self.apply_dark_theme()
        
        # Create central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Create menu bar
        self.create_menu_bar()
        
        # Create tab widget
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)
        
        # Create dashboard tab
        self.create_dashboard_tab()
        
        # Create terminal tab
        self.create_terminal_tab()
        
        # Create monitoring tab
        self.create_monitoring_tab()
        
        # Create status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")
        
        # Start background monitoring
        self.start_background_tasks()
        
    def apply_dark_theme(self):
        # Set application style
        self.setStyleSheet("""
            QMainWindow {
                background-color: #000000;
            }
            QWidget {
                background-color: #000000;
                color: #00ff00;
                font-family: Consolas, Monospace;
            }
            QTabWidget::pane {
                border: 1px solid #00ff00;
                background-color: #000000;
            }
            QTabBar::tab {
                background-color: #001100;
                color: #00ff00;
                padding: 8px;
                border: 1px solid #00ff00;
            }
            QTabBar::tab:selected {
                background-color: #003300;
            }
            QTextEdit {
                background-color: #001100;
                color: #00ff00;
                border: 1px solid #00ff00;
                font-family: Consolas, Monospace;
            }
            QLineEdit {
                background-color: #001100;
                color: #00ff00;
                border: 1px solid #00ff00;
                font-family: Consolas, Monospace;
                padding: 5px;
            }
            QPushButton {
                background-color: #001100;
                color: #00ff00;
                border: 1px solid #00ff00;
                padding: 5px;
                font-family: Consolas, Monospace;
            }
            QPushButton:hover {
                background-color: #003300;
            }
            QPushButton:pressed {
                background-color: #004400;
            }
            QMenuBar {
                background-color: #000000;
                color: #00ff00;
            }
            QMenuBar::item:selected {
                background-color: #003300;
            }
            QMenu {
                background-color: #000000;
                color: #00ff00;
                border: 1px solid #00ff00;
            }
            QMenu::item:selected {
                background-color: #003300;
            }
            QStatusBar {
                background-color: #001100;
                color: #00ff00;
            }
            QListWidget {
                background-color: #001100;
                color: #00ff00;
                border: 1px solid #00ff00;
                font-family: Consolas, Monospace;
            }
            QTableWidget {
                background-color: #001100;
                color: #00ff00;
                border: 1px solid #00ff00;
                gridline-color: #00ff00;
                font-family: Consolas, Monospace;
            }
            QHeaderView::section {
                background-color: #002200;
                color: #00ff00;
                padding: 4px;
                border: 1px solid #00ff00;
            }
        """)
        
    def create_menu_bar(self):
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu('File')
        
        export_action = QAction('Export Data', self)
        export_action.triggered.connect(self.export_data)
        file_menu.addAction(export_action)
        
        exit_action = QAction('Exit', self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # View menu
        view_menu = menubar.addMenu('View')
        
        dashboard_action = QAction('Dashboard', self)
        dashboard_action.triggered.connect(lambda: self.tabs.setCurrentIndex(0))
        view_menu.addAction(dashboard_action)
        
        terminal_action = QAction('Terminal', self)
        terminal_action.triggered.connect(lambda: self.tabs.setCurrentIndex(1))
        view_menu.addAction(terminal_action)
        
        monitoring_action = QAction('Monitoring', self)
        monitoring_action.triggered.connect(lambda: self.tabs.setCurrentIndex(2))
        view_menu.addAction(monitoring_action)
        
        # Tools menu
        tools_menu = menubar.addMenu('Tools')
        
        network_scan_action = QAction('Network Scan', self)
        network_scan_action.triggered.connect(self.network_scan)
        tools_menu.addAction(network_scan_action)
        
        packet_analyzer_action = QAction('Packet Analyzer', self)
        packet_analyzer_action.triggered.connect(self.packet_analyzer)
        tools_menu.addAction(packet_analyzer_action)
        
        # Settings menu
        settings_menu = menubar.addMenu('Settings')
        
        telegram_config_action = QAction('Telegram Configuration', self)
        telegram_config_action.triggered.connect(self.config_telegram)
        settings_menu.addAction(telegram_config_action)
        
        theme_action = QAction('Change Theme', self)
        theme_action.triggered.connect(self.change_theme)
        settings_menu.addAction(theme_action)
        
        # Help menu
        help_menu = menubar.addMenu('Help')
        
        about_action = QAction('About', self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
        
        docs_action = QAction('Documentation', self)
        docs_action.triggered.connect(self.show_documentation)
        help_menu.addAction(docs_action)
        
    def create_dashboard_tab(self):
        dashboard_tab = QWidget()
        layout = QVBoxLayout(dashboard_tab)
        
        # Create status overview
        status_frame = QFrame()
        status_frame.setFrameStyle(QFrame.StyledPanel)
        status_layout = QGridLayout(status_frame)
        
        self.packet_count_label = QLabel("Packets Monitored: 0")
        self.threat_count_label = QLabel("Threats Detected: 0")
        self.microwave_count_label = QLabel("Microwave Interceptions: 0")
        self.active_monitoring_label = QLabel("Active Monitoring: 0 IPs")
        
        status_layout.addWidget(self.packet_count_label, 0, 0)
        status_layout.addWidget(self.threat_count_label, 0, 1)
        status_layout.addWidget(self.microwave_count_label, 1, 0)
        status_layout.addWidget(self.active_monitoring_label, 1, 1)
        
        layout.addWidget(status_frame)
        
        # Create charts area
        charts_splitter = QSplitter(Qt.Horizontal)
        
        # Real-time traffic chart
        traffic_widget = QWidget()
        traffic_layout = QVBoxLayout(traffic_widget)
        traffic_layout.addWidget(QLabel("Real-time Network Traffic"))
        self.traffic_canvas = RealTimePlot(width=5, height=4, dpi=100)
        self.traffic_canvas.axes.set_title("Network Traffic Over Time")
        self.traffic_canvas.axes.set_xlabel("Time")
        self.traffic_canvas.axes.set_ylabel("Packets/sec")
        traffic_layout.addWidget(self.traffic_canvas)
        
        # Threat distribution chart
        threat_widget = QWidget()
        threat_layout = QVBoxLayout(threat_widget)
        threat_layout.addWidget(QLabel("Threat Distribution"))
        self.threat_figure = Figure(figsize=(5, 4), dpi=100)
        self.threat_canvas = FigureCanvas(self.threat_figure)
        self.threat_ax = self.threat_figure.add_subplot(111)
        threat_layout.addWidget(self.threat_canvas)
        
        charts_splitter.addWidget(traffic_widget)
        charts_splitter.addWidget(threat_widget)
        layout.addWidget(charts_splitter)
        
        # Recent threats table
        layout.addWidget(QLabel("Recent Threats"))
        self.threat_table = QTableWidget()
        self.threat_table.setColumnCount(4)
        self.threat_table.setHorizontalHeaderLabels(["Time", "IP Address", "Threat Type", "Severity"])
        self.threat_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.threat_table)
        
        self.tabs.addTab(dashboard_tab, "Dashboard")
        
    def create_terminal_tab(self):
        terminal_tab = QWidget()
        layout = QVBoxLayout(terminal_tab)
        
        # Terminal output
        self.terminal_output = QTextEdit()
        self.terminal_output.setReadOnly(True)
        layout.addWidget(self.terminal_output)
        
        # Terminal input area
        input_layout = QHBoxLayout()
        self.terminal_input = QLineEdit()
        self.terminal_input.returnPressed.connect(self.execute_command)
        input_layout.addWidget(self.terminal_input)
        
        send_button = QPushButton("Send")
        send_button.clicked.connect(self.execute_command)
        input_layout.addWidget(send_button)
        
        clear_button = QPushButton("Clear")
        clear_button.clicked.connect(self.terminal_output.clear)
        input_layout.addWidget(clear_button)
        
        layout.addLayout(input_layout)
        
        self.tabs.addTab(terminal_tab, "Terminal")
        
    def create_monitoring_tab(self):
        monitoring_tab = QWidget()
        layout = QHBoxLayout(monitoring_tab)
        
        # Left panel - IP management
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        
        left_layout.addWidget(QLabel("Monitored IP Addresses"))
        self.ip_list = QListWidget()
        left_layout.addWidget(self.ip_list)
        
        ip_management_layout = QHBoxLayout()
        add_ip_button = QPushButton("Add IP")
        add_ip_button.clicked.connect(self.add_ip_dialog)
        ip_management_layout.addWidget(add_ip_button)
        
        remove_ip_button = QPushButton("Remove IP")
        remove_ip_button.clicked.connect(self.remove_ip)
        ip_management_layout.addWidget(remove_ip_button)
        
        left_layout.addLayout(ip_management_layout)
        
        start_all_button = QPushButton("Start Monitoring All")
        start_all_button.clicked.connect(self.start_all_monitoring)
        left_layout.addWidget(start_all_button)
        
        stop_all_button = QPushButton("Stop Monitoring All")
        stop_all_button.clicked.connect(self.stop_all_monitoring)
        left_layout.addWidget(stop_all_button)
        
        # Right panel - IP details
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        
        right_layout.addWidget(QLabel("IP Details"))
        self.ip_details = QTextEdit()
        self.ip_details.setReadOnly(True)
        right_layout.addWidget(self.ip_details)
        
        # Splitter for left and right panels
        splitter = QSplitter(Qt.Horizontal)
        splitter.addWidget(left_panel)
        splitter.addWidget(right_panel)
        splitter.setSizes([300, 700])
        
        layout.addWidget(splitter)
        
        self.tabs.addTab(monitoring_tab, "Monitoring")
        
    def setup_connections(self):
        self.update_signal.connect(self.update_ui)
        self.telegram_signal.connect(self.send_telegram_message)
        self.ip_list.currentItemChanged.connect(self.show_ip_details)
        
    def load_config(self):
        try:
            with open('config.json', 'r') as f:
                config = json.load(f)
                self.telegram_token = config.get('telegram_token')
                self.telegram_chat_id = config.get('telegram_chat_id')
                
                # Load monitored IPs
                for ip in config.get('monitored_ips', []):
                    self.monitoring_ips[ip] = {
                        'status': 'stopped',
                        'packet_count': 0,
                        'threat_count': 0,
                        'last_activity': None
                    }
                    self.ip_list.addItem(ip)
                    
        except FileNotFoundError:
            self.log_terminal("No configuration file found. Starting with default settings.")
            
    def save_config(self):
        config = {
            'telegram_token': self.telegram_token,
            'telegram_chat_id': self.telegram_chat_id,
            'monitored_ips': list(self.monitoring_ips.keys())
        }
        
        with open('config.json', 'w') as f:
            json.dump(config, f, indent=4)
            
    def start_background_tasks(self):
        # Start packet monitoring thread
        self.monitoring_thread = threading.Thread(target=self.packet_monitoring_loop, daemon=True)
        self.monitoring_thread.start()
        
        # Start chart update timer
        self.chart_timer = QTimer()
        self.chart_timer.timeout.connect(self.update_charts)
        self.chart_timer.start(1000)  # Update every second
        
    def packet_monitoring_loop(self):
        while True:
            try:
                # Use scapy to sniff packets (limited to 10 packets per iteration)
                packets = scapy.sniff(count=10, timeout=1, filter="ip")
                
                for packet in packets:
                    self.packet_count += 1
                    src_ip = packet[scapy.IP].src
                    dst_ip = packet[scapy.IP].dst
                    
                    # Check if packet is from/to monitored IPs
                    monitored_ips = [ip for ip in self.monitoring_ips.keys() if self.monitoring_ips[ip]['status'] == 'monitoring']
                    
                    for ip in monitored_ips:
                        if src_ip == ip or dst_ip == ip:
                            self.monitoring_ips[ip]['packet_count'] += 1
                            self.monitoring_ips[ip]['last_activity'] = datetime.datetime.now().isoformat()
                            
                            # Check for threats
                            threat_detected = self.detect_threats(packet, ip)
                            if threat_detected:
                                self.threat_count += 1
                                self.monitoring_ips[ip]['threat_count'] += 1
                                self.log_threat(ip, threat_detected, "High")
                                
                            # Check for microwave interception patterns
                            if self.detect_microwave_interception(packet):
                                self.microwave_interception_count += 1
                                self.log_threat(ip, "Microwave Interception Detected", "Critical")
                                
                # Update traffic data for chart
                current_time = datetime.datetime.now()
                self.traffic_canvas.xdata.append(current_time)
                self.traffic_canvas.ydata.append(len(packets))
                
            except Exception as e:
                self.log_terminal(f"Error in packet monitoring: {str(e)}")
                
            time.sleep(0.1)  # Small delay to prevent excessive CPU usage
            
    def detect_threats(self, packet, ip):
        # Implement real threat detection logic here
        # This is a simplified example - real implementation would be more comprehensive
        
        # Check for unusual packet sizes
        if len(packet) > 1500:  # Larger than typical MTU
            return "Oversized packet detected"
            
        # Check for suspicious ports (common attack vectors for SCADA)
        if packet.haslayer(scapy.TCP):
            tcp_layer = packet[scapy.TCP]
            suspicious_ports = [502, 4840, 1911, 20000]  # Common SCADA/ICS ports
            if tcp_layer.dport in suspicious_ports or tcp_layer.sport in suspicious_ports:
                # Check for unusual flags (e.g., Xmas scan)
                if tcp_layer.flags == 'FPU':  # FIN, PSH, URG flags set (Xmas scan)
                    return "Xmas scan detected on SCADA port"
                    
        # Check for ICMP flooding (potential DoS)
        if packet.haslayer(scapy.ICMP):
            # In a real implementation, we would track ICMP rates over time
            return "ICMP packet detected (potential reconnaissance)"
            
        # Check for abnormal TCP patterns
        if packet.haslayer(scapy.TCP):
            tcp_layer = packet[scapy.TCP]
            # Check for null scan (no flags set)
            if tcp_layer.flags == 0:
                return "Null scan detected"
                
        return None
        
    def detect_microwave_interception(self, packet):
        # Microwave interception detection is complex and would typically require
        # specialized hardware or deep packet inspection for specific patterns
        
        # This is a simplified placeholder implementation
        # Real implementation would analyze signal characteristics, timing, etc.
        
        # Check for abnormal TTL values that might indicate interception
        if packet.haslayer(scapy.IP):
            ip_layer = packet[scapy.IP]
            if ip_layer.ttl < 5:  # Unusually low TTL might indicate interception
                return True
                
        # Check for specific patterns in packet timing or structure
        # that might indicate microwave interception
        
        return False
        
    def log_threat(self, ip, threat_type, severity):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        message = f"[{timestamp}] THREAT ALERT: {threat_type} from {ip} - Severity: {severity}"
        
        # Update UI
        self.update_signal.emit(message)
        
        # Send to Telegram if configured
        if self.telegram_token and self.telegram_chat_id:
            self.telegram_signal.emit(f"SCADA Security Alert: {threat_type}", message)
            
        # Add to threats table
        row_position = self.threat_table.rowCount()
        self.threat_table.insertRow(row_position)
        self.threat_table.setItem(row_position, 0, QTableWidgetItem(timestamp))
        self.threat_table.setItem(row_position, 1, QTableWidgetItem(ip))
        self.threat_table.setItem(row_position, 2, QTableWidgetItem(threat_type))
        self.threat_table.setItem(row_position, 3, QTableWidgetItem(severity))
        
    def log_terminal(self, message):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        formatted_message = f"[{timestamp}] {message}"
        self.terminal_output.append(formatted_message)
        
    def update_ui(self, message):
        self.terminal_output.append(message)
        self.packet_count_label.setText(f"Packets Monitored: {self.packet_count}")
        self.threat_count_label.setText(f"Threats Detected: {self.threat_count}")
        self.microwave_count_label.setText(f"Microwave Interceptions: {self.microwave_interception_count}")
        self.active_monitoring_label.setText(f"Active Monitoring: {len([ip for ip in self.monitoring_ips.keys() if self.monitoring_ips[ip]['status'] == 'monitoring'])} IPs")
        
    def update_charts(self):
        # Update real-time traffic chart
        self.traffic_canvas.update_plot()
        
        # Update threat distribution chart
        self.threat_ax.clear()
        
        # Sample data for threat distribution
        threat_types = ['Port Scan', 'ICMP Flood', 'Oversized Packet', 'Microwave']
        threat_counts = [12, 5, 3, self.microwave_interception_count]  # Example data
        
        self.threat_ax.bar(threat_types, threat_counts, color=['red', 'orange', 'yellow', 'purple'])
        self.threat_ax.set_title('Threat Distribution')
        self.threat_ax.set_ylabel('Count')
        self.threat_canvas.draw()
        
    def execute_command(self):
        command = self.terminal_input.text().strip()
        self.terminal_input.clear()
        
        if not command:
            return
            
        # Add to command history
        self.command_history.append(command)
        self.history_index = len(self.command_history)
        
        # Process command
        parts = command.split()
        cmd = parts[0].lower()
        
        self.log_terminal(f"> {command}")
        
        if cmd == "help":
            self.show_help()
        elif cmd == "ping" and len(parts) > 1:
            self.ping_ip(parts[1])
        elif cmd == "start" and len(parts) > 2 and parts[1] == "monitoring":
            self.start_monitoring_ip(parts[2])
        elif cmd == "stop":
            self.stop_monitoring()
        elif cmd == "view":
            self.view_status()
        elif cmd == "exit":
            self.close()
        elif cmd == "status":
            self.show_status()
        elif cmd == "add" and len(parts) > 1:
            self.add_ip(parts[1])
        elif cmd == "remove" and len(parts) > 1:
            self.remove_ip(parts[1])
        elif cmd == "udptraceroute" and len(parts) > 1:
            self.udp_traceroute(parts[1])
        elif cmd == "tcptraceroute" and len(parts) > 1:
            self.tcp_traceroute(parts[1])
        elif cmd == "config" and len(parts) > 2:
            if parts[1] == "telegram" and parts[2] == "token" and len(parts) > 3:
                self.config_telegram_token(parts[3])
            elif parts[1] == "telegram" and parts[2] == "chat_id" and len(parts) > 3:
                self.config_telegram_chat_id(parts[3])
        elif cmd == "test" and len(parts) > 1 and parts[1] == "telegram":
            self.test_telegram_connection()
        elif cmd == "clear":
            self.terminal_output.clear()
        elif cmd == "history":
            self.show_command_history()
        else:
            self.log_terminal(f"Unknown command: {command}. Type 'help' for available commands.")
            
    def show_help(self):
        help_text = """
Available commands:
  help - Show this help message
  ping <ip> - Ping an IP address
  start monitoring <ip> - Start monitoring an IP address
  stop - Stop all monitoring
  view - View current monitoring status
  exit - Exit the application
  status - Show detailed status
  add ip <ip> - Add an IP address to monitor
  remove ip <ip> - Remove an IP address from monitoring
  udptraceroute <ip> - Perform UDP traceroute to an IP
  tcptraceroute <ip> - Perform TCP traceroute to an IP
  config telegram token <token> - Set Telegram bot token
  config telegram chat_id <id> - Set Telegram chat ID
  test telegram - Test Telegram connection
  clear - Clear terminal output
  history - Show command history
"""
        self.log_terminal(help_text)
        
    def ping_ip(self, ip):
        try:
            # Validate IP address
            socket.inet_aton(ip)
            
            # Run ping command
            param = "-n" if sys.platform.lower().startswith("win") else "-c"
            command = ["ping", param, "4", ip]
            result = subprocess.run(command, capture_output=True, text=True, timeout=10)
            
            self.log_terminal(result.stdout)
            if result.stderr:
                self.log_terminal(result.stderr)
                
        except socket.error:
            self.log_terminal(f"Invalid IP address: {ip}")
        except subprocess.TimeoutExpired:
            self.log_terminal("Ping command timed out")
        except Exception as e:
            self.log_terminal(f"Error executing ping: {str(e)}")
            
    def start_monitoring_ip(self, ip):
        if ip in self.monitoring_ips:
            if self.monitoring_ips[ip]['status'] == 'monitoring':
                self.log_terminal(f"Already monitoring {ip}")
            else:
                self.monitoring_ips[ip]['status'] = 'monitoring'
                self.log_terminal(f"Started monitoring {ip}")
        else:
            self.monitoring_ips[ip] = {
                'status': 'monitoring',
                'packet_count': 0,
                'threat_count': 0,
                'last_activity': None
            }
            self.ip_list.addItem(ip)
            self.log_terminal(f"Added and started monitoring {ip}")
            
        self.save_config()
        
    def stop_monitoring(self):
        for ip in self.monitoring_ips:
            self.monitoring_ips[ip]['status'] = 'stopped'
        self.log_terminal("Stopped all monitoring")
        
    def view_status(self):
        status_text = "Current Monitoring Status:\n"
        for ip, data in self.monitoring_ips.items():
            status = data['status']
            packet_count = data['packet_count']
            threat_count = data['threat_count']
            last_activity = data['last_activity'] or "Never"
            status_text += f"{ip}: {status}, Packets: {packet_count}, Threats: {threat_count}, Last: {last_activity}\n"
            
        self.log_terminal(status_text)
        
    def show_status(self):
        self.view_status()  # Same as view command for now
        
    def add_ip(self, ip):
        if ip in self.monitoring_ips:
            self.log_terminal(f"IP {ip} is already in the monitoring list")
        else:
            self.monitoring_ips[ip] = {
                'status': 'stopped',
                'packet_count': 0,
                'threat_count': 0,
                'last_activity': None
            }
            self.ip_list.addItem(ip)
            self.log_terminal(f"Added {ip} to monitoring list")
            self.save_config()
            
    def remove_ip(self, ip):
        if ip in self.monitoring_ips:
            del self.monitoring_ips[ip]
            items = self.ip_list.findItems(ip, Qt.MatchExactly)
            for item in items:
                self.ip_list.takeItem(self.ip_list.row(item))
            self.log_terminal(f"Removed {ip} from monitoring list")
            self.save_config()
        else:
            self.log_terminal(f"IP {ip} not found in monitoring list")
            
    def udp_traceroute(self, ip):
        try:
            # Validate IP address
            socket.inet_aton(ip)
            
            # Run traceroute command
            param = "-w" if sys.platform.lower().startswith("win") else "-w"
            command = ["tracert", param, "3", ip] if sys.platform.lower().startswith("win") else ["traceroute", "-w", "3", ip]
            result = subprocess.run(command, capture_output=True, text=True, timeout=30)
            
            self.log_terminal(result.stdout)
            if result.stderr:
                self.log_terminal(result.stderr)
                
        except socket.error:
            self.log_terminal(f"Invalid IP address: {ip}")
        except subprocess.TimeoutExpired:
            self.log_terminal("Traceroute command timed out")
        except Exception as e:
            self.log_terminal(f"Error executing traceroute: {str(e)}")
            
    def tcp_traceroute(self, ip):
        # TCP traceroute implementation would be more complex
        # For now, we'll use the same as UDP traceroute
        self.log_terminal("TCP traceroute is not yet implemented. Using standard traceroute.")
        self.udp_traceroute(ip)
        
    def config_telegram_token(self, token):
        self.telegram_token = token
        self.save_config()
        self.log_terminal("Telegram token configured")
        
    def config_telegram_chat_id(self, chat_id):
        self.telegram_chat_id = chat_id
        self.save_config()
        self.log_terminal("Telegram chat ID configured")
        
    def test_telegram_connection(self):
        if not self.telegram_token or not self.telegram_chat_id:
            self.log_terminal("Telegram not configured. Please set token and chat ID first.")
            return
            
        try:
            url = f"https://api.telegram.org/bot{self.telegram_token}/getMe"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                self.log_terminal("Telegram connection test successful")
            else:
                self.log_terminal(f"Telegram connection test failed: {response.status_code}")
                
        except Exception as e:
            self.log_terminal(f"Telegram connection test error: {str(e)}")
            
    def show_command_history(self):
        history_text = "Command History:\n"
        for i, cmd in enumerate(self.command_history):
            history_text += f"{i+1}. {cmd}\n"
            
        self.log_terminal(history_text)
        
    def send_telegram_message(self, title, message):
        if not self.telegram_token or not self.telegram_chat_id:
            return
            
        try:
            url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
            payload = {
                'chat_id': self.telegram_chat_id,
                'text': f"{title}\n\n{message}",
                'parse_mode': 'HTML'
            }
            
            response = requests.post(url, data=payload, timeout=10)
            if response.status_code != 200:
                self.log_terminal(f"Failed to send Telegram message: {response.status_code}")
                
        except Exception as e:
            self.log_terminal(f"Error sending Telegram message: {str(e)}")
            
    def show_ip_details(self, current, previous):
        if current is None:
            self.ip_details.clear()
            return
            
        ip = current.text()
        if ip in self.monitoring_ips:
            data = self.monitoring_ips[ip]
            details = f"""
IP Address: {ip}
Status: {data['status']}
Packets Monitored: {data['packet_count']}
Threats Detected: {data['threat_count']}
Last Activity: {data['last_activity'] or 'Never'}
"""
            self.ip_details.setText(details)
            
    def add_ip_dialog(self):
        ip, ok = QInputDialog.getText(self, "Add IP", "Enter IP address to monitor:")
        if ok and ip:
            self.add_ip(ip)
            
    def start_all_monitoring(self):
        for ip in self.monitoring_ips:
            self.monitoring_ips[ip]['status'] = 'monitoring'
        self.log_terminal("Started monitoring all IPs")
        
    def stop_all_monitoring(self):
        for ip in self.monitoring_ips:
            self.monitoring_ips[ip]['status'] = 'stopped'
        self.log_terminal("Stopped monitoring all IPs")
        
    def export_data(self):
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getSaveFileName(self, "Export Data", "", "CSV Files (*.csv);;JSON Files (*.json)", options=options)
        
        if file_name:
            if file_name.endswith('.csv'):
                self.export_to_csv(file_name)
            elif file_name.endswith('.json'):
                self.export_to_json(file_name)
            else:
                self.log_terminal("Unsupported file format")
                
    def export_to_csv(self, file_name):
        try:
            data = []
            for ip, details in self.monitoring_ips.items():
                data.append({
                    'IP': ip,
                    'Status': details['status'],
                    'Packets': details['packet_count'],
                    'Threats': details['threat_count'],
                    'Last Activity': details['last_activity'] or 'Never'
                })
                
            df = pd.DataFrame(data)
            df.to_csv(file_name, index=False)
            self.log_terminal(f"Data exported to {file_name}")
            
        except Exception as e:
            self.log_terminal(f"Error exporting to CSV: {str(e)}")
            
    def export_to_json(self, file_name):
        try:
            with open(file_name, 'w') as f:
                json.dump(self.monitoring_ips, f, indent=4)
            self.log_terminal(f"Data exported to {file_name}")
            
        except Exception as e:
            self.log_terminal(f"Error exporting to JSON: {str(e)}")
            
    def network_scan(self):
        self.log_terminal("Network scan feature is not yet implemented")
        
    def packet_analyzer(self):
        self.log_terminal("Packet analyzer feature is not yet implemented")
        
    def config_telegram(self):
        token, ok1 = QInputDialog.getText(self, "Telegram Configuration", "Enter Telegram bot token:")
        if ok1 and token:
            self.config_telegram_token(token)
            
        chat_id, ok2 = QInputDialog.getText(self, "Telegram Configuration", "Enter Telegram chat ID:")
        if ok2 and chat_id:
            self.config_telegram_chat_id(chat_id)
            
    def change_theme(self):
        self.log_terminal("Theme change feature is not yet implemented")
        
    def show_about(self):
        about_text = """
SCADA Cyber Security Monitoring Tool
Version 11.0

A comprehensive tool for monitoring SCADA systems against cyber threats.
Features include real-time packet monitoring, threat detection, and alerting.

Designed for industrial control system security.
"""
        QMessageBox.about(self, "About", about_text)
        
    def show_documentation(self):
        doc_text = """
SCADA Cyber Security Monitoring Tool Documentation

Ian Carter Kulani
E-mail:iancarterkulani@gmail.com
Phone:+265988061969
1. Dashboard: View overall statistics and threat distribution charts.
2. Terminal: Execute commands for monitoring and configuration.
3. Monitoring: Manage monitored IP addresses and view details.

Key Features:
- Real-time packet monitoring
- Threat detection including microwave interception
- Telegram integration for alerts
- Export capabilities for data analysis

For detailed usage instructions, refer to the user manual.
"""
        QMessageBox.information(self, "Documentation", doc_text)
        
    def closeEvent(self, event):
        reply = QMessageBox.question(self, 'Exit', 'Are you sure you want to exit?', 
                                   QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            self.save_config()
            event.accept()
        else:
            event.ignore()

def main():
    app = QApplication(sys.argv)
    
    # Set application font
    font = QFont("Consolas", 10)
    app.setFont(font)
    
    window = CyberSecurityTool()
    window.show()
    
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()