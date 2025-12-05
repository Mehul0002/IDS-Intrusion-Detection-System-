import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from tkinter.scrolledtext import ScrolledText
import threading
from packet_capture import PacketCapture
from port_scan_detector import PortScanDetector
from payload_detector import PayloadDetector

class IDS_GUI:
    """
    Main GUI class for the IDS Mini application.
    """

    def __init__(self, root):
        """
        Initialize the GUI.
        """
        self.root = root
        self.root.title("IDS Mini - Intrusion Detection System")
        self.root.geometry("1000x700")

        # Initialize components
        self.packet_capture = PacketCapture(callback=self.process_packet)
        self.port_detector = PortScanDetector(alert_callback=self.add_alert)
        self.payload_detector = PayloadDetector(alert_callback=self.add_alert)

        # Packet and alert counters
        self.packet_count = 0
        self.alert_count = 0

        # Create GUI elements
        self.create_menu()
        self.create_widgets()
        self.create_status_bar()

        # Start GUI update thread
        self.update_thread = threading.Thread(target=self.update_gui_loop, daemon=True)
        self.update_thread.start()

    def create_menu(self):
        """
        Create the top menu bar.
        """
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Export Logs", command=self.export_logs)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)

        # Capture menu
        capture_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Capture", menu=capture_menu)
        capture_menu.add_command(label="Start Capture", command=self.start_capture)
        capture_menu.add_command(label="Stop Capture", command=self.stop_capture)

    def create_widgets(self):
        """
        Create the main widgets: packet viewer and alerts panel.
        """
        # Main frame
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Packet Viewer Panel
        packet_frame = ttk.LabelFrame(main_frame, text="Packet Viewer")
        packet_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, pady=(0, 10))

        # Treeview for packets
        columns = ('Time', 'Source IP', 'Dest IP', 'Protocol', 'Length')
        self.packet_tree = ttk.Treeview(packet_frame, columns=columns, show='headings', height=15)
        for col in columns:
            self.packet_tree.heading(col, text=col)
            self.packet_tree.column(col, width=120)
        self.packet_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Scrollbar for treeview
        tree_scroll = ttk.Scrollbar(packet_frame, orient=tk.VERTICAL, command=self.packet_tree.yview)
        self.packet_tree.configure(yscrollcommand=tree_scroll.set)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # Alerts Panel
        alerts_frame = ttk.LabelFrame(main_frame, text="Alerts")
        alerts_frame.pack(side=tk.BOTTOM, fill=tk.BOTH, expand=True)

        self.alerts_text = ScrolledText(alerts_frame, height=10, wrap=tk.WORD)
        self.alerts_text.pack(fill=tk.BOTH, expand=True)
        self.alerts_text.tag_configure("alert", foreground="red", font=("Arial", 10, "bold"))
        self.alerts_text.tag_configure("warning", foreground="orange", font=("Arial", 10, "bold"))

    def create_status_bar(self):
        """
        Create the status bar at the bottom.
        """
        self.status_frame = ttk.Frame(self.root)
        self.status_frame.pack(side=tk.BOTTOM, fill=tk.X)

        self.status_label = ttk.Label(self.status_frame, text="Status: Stopped")
        self.status_label.pack(side=tk.LEFT, padx=10)

        self.packet_label = ttk.Label(self.status_frame, text="Packets: 0")
        self.packet_label.pack(side=tk.LEFT, padx=10)

        self.alerts_label = ttk.Label(self.status_frame, text="Alerts: 0")
        self.alerts_label.pack(side=tk.LEFT, padx=10)

    def start_capture(self):
        """
        Start packet capturing.
        """
        if not self.packet_capture.sniffing:
            self.packet_capture.start_capture()
            self.status_label.config(text="Status: Running")
            messagebox.showinfo("Capture Started", "Packet capture has started.")

    def stop_capture(self):
        """
        Stop packet capturing.
        """
        self.packet_capture.stop_capture()
        self.status_label.config(text="Status: Stopped")
        messagebox.showinfo("Capture Stopped", "Packet capture has stopped.")

    def process_packet(self, packet_info):
        """
        Process a captured packet: update GUI, check for alerts.
        """
        # Update packet count
        self.packet_count += 1

        # Add to packet tree
        self.add_packet_to_tree(packet_info)

        # Check for port scan
        self.port_detector.process_packet(packet_info)

        # Check for suspicious payload
        self.payload_detector.process_packet(packet_info)

    def add_packet_to_tree(self, packet_info):
        """
        Add packet info to the treeview.
        """
        # Use thread-safe way: queue the update
        self.root.after(0, lambda: self._insert_packet(packet_info))

    def _insert_packet(self, packet_info):
        """
        Insert packet into treeview (called in main thread).
        """
        values = (
            packet_info['timestamp'],
            packet_info['src_ip'] or 'N/A',
            packet_info['dst_ip'] or 'N/A',
            packet_info['protocol'] or 'N/A',
            packet_info['length'] or 0
        )
        self.packet_tree.insert('', tk.END, values=values)
        # Auto-scroll to bottom
        self.packet_tree.yview_moveto(1)

    def add_alert(self, alert):
        """
        Add an alert to the alerts panel and show popup.
        """
        self.alert_count += 1
        self.root.after(0, lambda: self._insert_alert(alert))

    def _insert_alert(self, alert):
        """
        Insert alert into text widget (called in main thread).
        """
        text = f"[{alert['timestamp']}] {alert['type']}: {alert['src_ip']} - {alert['details']}\n"
        self.alerts_text.insert(tk.END, text, "alert")
        self.alerts_text.see(tk.END)

        # Show popup
        messagebox.showwarning("Alert", f"{alert['type']}\nSource: {alert['src_ip']}\n{alert['details']}")

    def update_gui_loop(self):
        """
        Loop to update status bar periodically.
        """
        while True:
            self.root.after(1000, self.update_status)

    def update_status(self):
        """
        Update the status bar labels.
        """
        self.packet_label.config(text=f"Packets: {self.packet_count}")
        self.alerts_label.config(text=f"Alerts: {self.alert_count}")

    def export_logs(self):
        """
        Export alerts to a file.
        """
        filename = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("CSV files", "*.csv")])
        if filename:
            with open(filename, 'w') as f:
                f.write(self.alerts_text.get(1.0, tk.END))
            messagebox.showinfo("Export", "Logs exported successfully.")
