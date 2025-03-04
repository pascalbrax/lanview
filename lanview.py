import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading, queue, time, socket, ipaddress, requests, sys
import psutil
from ping3 import ping
from scapy.all import ARP, Ether, srp

# pascal brax 2025

# Global queue for thread-to-GUI updates
update_queue = queue.Queue()

# Global flag to signal stopping the scan
scanning_stop = False

# Global counter for progress
scanned_count = 0

# A semaphore to limit concurrent threads; will be set when scan starts.
thread_semaphore = None

class LANScannerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("LAN Scanner")
        self.geometry("900x600")
        self.protocol("WM_DELETE_WINDOW", self.on_exit)

        # --- Variables ---
        self.selected_ip = tk.StringVar()
        self.num_threads_var = tk.StringVar(value="10")
        self.mac_vendor_var = tk.BooleanVar(value=False)
        self.status_var = tk.StringVar(value="Idle")

        # This will hold the mapping ip -> treeview item id
        self.table_items = {}

        # --- Create Widgets ---
        top_frame = ttk.Frame(self)
        top_frame.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)

        # Interface selection dropdown (populate with available IPv4 addresses)
        ttk.Label(top_frame, text="Interface IP:").pack(side=tk.LEFT, padx=2)
        self.ip_dropdown = ttk.Combobox(top_frame, textvariable=self.selected_ip, state="readonly", width=20)
        self.ip_dropdown['values'] = self.get_local_ips()
        if self.ip_dropdown['values']:
            # Use the first non-loopback IP as default.
            self.selected_ip.set(self.ip_dropdown['values'][0])
        self.ip_dropdown.pack(side=tk.LEFT, padx=2)

        # Number of threads
        ttk.Label(top_frame, text="Threads:").pack(side=tk.LEFT, padx=2)
        self.thread_entry = ttk.Entry(top_frame, textvariable=self.num_threads_var, width=5)
        self.thread_entry.pack(side=tk.LEFT, padx=2)

        # MAC vendor online checkbox
        self.mac_vendor_cb = ttk.Checkbutton(top_frame, text="Use Online MAC DB", variable=self.mac_vendor_var)
        self.mac_vendor_cb.pack(side=tk.LEFT, padx=10)

        # Buttons
        self.start_btn = ttk.Button(top_frame, text="Start Scan", command=self.start_scan)
        self.start_btn.pack(side=tk.LEFT, padx=2)
        self.stop_btn = ttk.Button(top_frame, text="Stop Scan", command=self.stop_scan, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=2)
        self.export_btn = ttk.Button(top_frame, text="Export", command=self.export_results)
        self.export_btn.pack(side=tk.LEFT, padx=2)
        self.exit_btn = ttk.Button(top_frame, text="Exit", command=self.on_exit)
        self.exit_btn.pack(side=tk.LEFT, padx=2)

        # --- Progress Bar ---
        self.progress_bar = ttk.Progressbar(self, orient="horizontal", mode="determinate")
        self.progress_bar.pack(fill=tk.X, padx=5, pady=5)

        # --- IP Table ---
        table_frame = ttk.Frame(self)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        columns = ("IP", "Ping", "Hostname", "MAC Address", "MAC Vendor")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings")
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=120, anchor="w")
        # Add vertical scrollbar
        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

        # --- Log Window ---
        log_frame = ttk.LabelFrame(self, text="Log")
        log_frame.pack(fill=tk.BOTH, padx=5, pady=5, expand=False)
        self.log_text = tk.Text(log_frame, height=8)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        log_vsb = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_vsb.set)
        log_vsb.pack(side=tk.RIGHT, fill=tk.Y)

        # --- Status Bar ---
        self.status_bar = ttk.Label(self, textvariable=self.status_var, relief=tk.SUNKEN, anchor="w")
        self.status_bar.pack(fill=tk.X, padx=5, pady=2)

        # Configure tags for color coding (green for ping, blue for ARP)
        self.tree.tag_configure("green", foreground="green")
        self.tree.tag_configure("blue", foreground="blue")

        # Start the periodic queue processor
        self.process_queue()

    def get_local_ips(self):
        """Retrieve IPv4 addresses from available interfaces (excluding loopback)."""
        ips = []
        for iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                    ips.append(addr.address)
        return ips

    def start_scan(self):
        global scanning_stop, scanned_count, thread_semaphore
        scanning_stop = False
        scanned_count = 0
        self.status_var.set("Scanning...")
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.log("Scan started.")

        # Clear previous table entries
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.table_items.clear()

        # Determine the network range from the selected interface.
        try:
            ip_addr = self.selected_ip.get()
            # Retrieve netmask for the selected interface
            netmask = None
            for iface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET and addr.address == ip_addr:
                        netmask = addr.netmask
                        break
                if netmask:
                    break
            if not netmask:
                messagebox.showerror("Error", "Unable to determine netmask for selected IP.")
                return

            # Calculate network (assume IPv4)
            network = ipaddress.IPv4Network(f"{ip_addr}/{netmask}", strict=False)
            ip_list = [str(ip) for ip in network.hosts()]
        except Exception as e:
            messagebox.showerror("Error", f"Error calculating network range: {e}")
            return

        # Set progress bar maximum.
        self.progress_bar.config(maximum=len(ip_list))
        self.log(f"Scanning network: {network} with {len(ip_list)} hosts.")

        # Create a semaphore to limit concurrent threads.
        try:
            max_threads = int(self.num_threads_var.get())
        except ValueError:
            messagebox.showerror("Error", "Thread count must be an integer.")
            return
        thread_semaphore = threading.BoundedSemaphore(max_threads)

        # Populate table with all IPs with default values.
        for ip in ip_list:
            item_id = self.tree.insert("", tk.END, values=(ip, "Pending...", "", "", ""))
            self.table_items[ip] = item_id

        # Start scanning threads for each IP.
        self.threads = []
        vendor_lookup = self.mac_vendor_var.get()
        for ip in ip_list:
            t = threading.Thread(target=scan_ip, args=(ip, vendor_lookup))
            t.daemon = True
            t.start()
            self.threads.append(t)
            self.log(f"Thread started for {ip}")

        # Start a monitor thread to wait for all scanning threads to finish.
        threading.Thread(target=self.monitor_scanning, daemon=True).start()

    def monitor_scanning(self):
        for t in self.threads:
            t.join()
        update_queue.put({"type": "done"})

    def stop_scan(self):
        global scanning_stop
        scanning_stop = True
        self.status_var.set("Stopping...")
        self.log("Stop requested by user.")
        self.stop_btn.config(state=tk.DISABLED)

    def export_results(self):
        # Export the current table data to a text file.
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files","*.csv"),("All files","*.*")])
        if not file_path:
            return
        try:
            with open(file_path, "w") as f:
                f.write("IP;Ping;Hostname;MAC Address;MAC Vendor\n")
                for item in self.tree.get_children():
                    values = self.tree.item(item)["values"]
                    #f.write("\t".join(str(v) for v in values) + "\n")
                    f.write(";".join(str(v) for v in values) + "\n")
            self.log(f"Results exported to {file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Error exporting results: {e}")

    def log(self, message):
        timestamp = time.strftime("%H:%M:%S")
        full_message = f"[{timestamp}] {message}\n"
        # Append to log text widget and also print to stdout.
        self.log_text.insert(tk.END, full_message)
        self.log_text.see(tk.END)
        print(full_message.strip())

    def process_queue(self):
        try:
            while True:
                item = update_queue.get_nowait()
                if item["type"] == "log":
                    self.log(item["message"])
                elif item["type"] == "result":
                    ip = item["ip"]
                    # Update the table row corresponding to the IP.
                    if ip in self.table_items:
                        item_id = self.table_items[ip]
                        # Set new values for the row.
                        self.tree.item(item_id, values=(ip, item["status"], item["hostname"], item["mac"], item["vendor"]))
                elif item["type"] == "progress":
                    self.progress_bar["value"] = item["progress"]
                elif item["type"] == "done":
                    self.finalize_scan()
        except queue.Empty:
            pass
        self.after(100, self.process_queue)

    def finalize_scan(self):
        # Remove rows that did not reply to ping and have no ARP MAC (i.e. offline and no ARP info).
        all_items = self.tree.get_children()
        for item in all_items:
            values = self.tree.item(item)["values"]
            ip, status, hostname, mac, vendor = values
            if status != "Online" and mac == "":
                self.tree.delete(item)
        # Retrieve remaining items and sort them by IP.
        items = []
        for item in self.tree.get_children():
            vals = self.tree.item(item)["values"]
            items.append((item, ipaddress.IPv4Address(vals[0]), vals))
        items.sort(key=lambda x: x[1])
        # Clear tree and reinsert in order.
        for item in self.tree.get_children():
            self.tree.delete(item)
        for item, addr, vals in items:
            # Color coding: green if ping reply, blue if ARP (and not ping).
            tag = ""
            if vals[1] == "Online":
                tag = "green"
            elif vals[3]:
                tag = "blue"
            new_id = self.tree.insert("", tk.END, values=vals, tags=(tag,))
        self.status_var.set("Scan complete.")
        total_ips = len(self.tree.get_children())
        self.log(f"Total IPs after cleanup: {total_ips}")
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.log("Scan complete.")

    def on_exit(self):
        if messagebox.askokcancel("Exit", "Are you sure you want to exit?"):
            global scanning_stop
            scanning_stop = True
            self.destroy()

# ------------------ Scanning Worker Function ------------------
def scan_ip(ip, vendor_lookup):
    global scanning_stop, scanned_count, thread_semaphore
    if scanning_stop:
        update_queue.put({"type": "log", "message": f"Scan cancelled for {ip}"})
        return
    update_queue.put({"type": "log", "message": f"Starting scan for {ip}"})
    # Limit concurrent threads via semaphore.
    with thread_semaphore:
        if scanning_stop:
            update_queue.put({"type": "log", "message": f"Scan cancelled for {ip}"})
            return

        # --- Step 1: Ping ---

        try:
            ping_result = ping(ip, timeout=1)
            # Log the raw ping result
            update_queue.put({"type": "log", "message": f"Ping result for {ip}: {ping_result}"})
            status = "Online" if ping_result else "No reply"
        except Exception as e:
            status = "Error"
            update_queue.put({"type": "log", "message": f"Ping error on {ip}: {e}"})

        
        # --- Step 2: DNS/NetBIOS Lookup ---
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except Exception:
            hostname = ""
        
        # --- Step 3: ARP Scan ---
        mac = ""
        try:
            # Send an ARP request packet to get MAC address.
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=1, verbose=False)
            if ans:
                mac = ans[0][1].hwsrc
        except Exception as e:
            update_queue.put({"type": "log", "message": f"ARP error on {ip}: {e}"})
        
        # --- Step 4: MAC Vendor Lookup (if enabled) ---
        vendor = ""
        if mac and vendor_lookup:
            try:
                url = "https://braile.ch/mac.php?mac=" + mac
                r = requests.get(url, timeout=3)
                vendor = r.text.strip()
            except Exception as e:
                update_queue.put({"type": "log", "message": f"MAC vendor lookup error on {ip}: {e}"})
        
        # Update the table with results.
        update_queue.put({
            "type": "result",
            "ip": ip,
            "status": status,
            "hostname": hostname,
            "mac": mac,
            "vendor": vendor
        })
        update_queue.put({"type": "log", "message": f"Finished scan for {ip}"})
        # Update progress.
        global scanned_count
        scanned_count += 1
        update_queue.put({"type": "progress", "progress": scanned_count})
        # Also print to stdout.
        print(f"Finished scanning {ip}: Status={status}, Hostname={hostname}, MAC={mac}, Vendor={vendor}")

# ------------------ Main ------------------
if __name__ == '__main__':
    app = LANScannerApp()
    app.mainloop()
