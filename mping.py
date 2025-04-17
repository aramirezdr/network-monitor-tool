import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import subprocess
import threading
import time
import queue
import re
from collections import deque
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import platform
import json
from datetime import datetime

class NetworkMonitor:
    def __init__(self, root):
        self.root = root
        self.root.title('Advanced Network Monitoring Tool')
        self.root.geometry('1000x800')
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Data storage
        self.ping_data = {}  # Dictionary to store ping data for each address
        self.traceroute_data = {}  # Dictionary to store traceroute results
        self.max_data_points = 100
        self.running = True
        self.active_threads = {}
        self.data_queue = queue.Queue()
        
        # Setup UI
        self.setup_ui()
        
        # Start queue processing thread
        self.queue_thread = threading.Thread(target=self.process_queue, daemon=True)
        self.queue_thread.start()
        
        # Schedule regular plot updates
        self.root.after(1000, self.update_canvas)

    def setup_ui(self):
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Create tabs
        self.ping_tab = ttk.Frame(self.notebook)
        self.traceroute_tab = ttk.Frame(self.notebook)
        
        self.notebook.add(self.ping_tab, text="Ping Monitor")
        self.notebook.add(self.traceroute_tab, text="Traceroute")
        
        # Setup ping tab UI
        self.setup_ping_tab()
        
        # Setup traceroute tab UI
        self.setup_traceroute_tab()

    def setup_ping_tab(self):
        # Create frames
        control_frame = ttk.LabelFrame(self.ping_tab, text="Controls")
        control_frame.pack(fill="x", padx=10, pady=5)
        
        status_frame = ttk.LabelFrame(self.ping_tab, text="Monitoring Status")
        status_frame.pack(fill="x", padx=10, pady=5)
        
        plot_frame = ttk.Frame(self.ping_tab)
        plot_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Control widgets
        ttk.Label(control_frame, text="Target address:").grid(row=0, column=0, padx=5, pady=5)
        self.address_entry = ttk.Entry(control_frame, width=30)
        self.address_entry.grid(row=0, column=1, padx=5, pady=5)
        self.address_entry.insert(0, "8.8.8.8")  # Default to Google DNS
        
        ttk.Label(control_frame, text="Ping interval (sec):").grid(row=0, column=2, padx=5, pady=5)
        self.interval_var = tk.DoubleVar(value=1.0)
        interval_spinner = ttk.Spinbox(control_frame, from_=0.5, to=10.0, increment=0.5, 
                                        textvariable=self.interval_var, width=5)
        interval_spinner.grid(row=0, column=3, padx=5, pady=5)
        
        self.start_button = ttk.Button(control_frame, text="Start Monitoring", command=self.start_ping)
        self.start_button.grid(row=0, column=4, padx=5, pady=5)
        
        self.stop_button = ttk.Button(control_frame, text="Stop", command=self.stop_ping)
        self.stop_button.grid(row=0, column=5, padx=5, pady=5)
        self.stop_button["state"] = "disabled"
        
        # Status widgets
        self.tree = ttk.Treeview(status_frame, columns=("Address", "Status", "Last RTT", "Avg RTT", "Loss %"))
        self.tree.heading("#0", text="")
        self.tree.column("#0", width=0, stretch=tk.NO)
        self.tree.heading("Address", text="Address")
        self.tree.heading("Status", text="Status")
        self.tree.heading("Last RTT", text="Last RTT (ms)")
        self.tree.heading("Avg RTT", text="Avg RTT (ms)")
        self.tree.heading("Loss %", text="Packet Loss %")
        
        for col in ("Address", "Status", "Last RTT", "Avg RTT", "Loss %"):
            self.tree.column(col, width=100, anchor="center")
        
        # Add scrollbar to treeview
        tree_scroll = ttk.Scrollbar(status_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=tree_scroll.set)
        tree_scroll.pack(side="right", fill="y")
        self.tree.pack(side="left", fill="both", expand=True)
        
        # Setup the plot
        self.fig, self.ax = plt.subplots(figsize=(8, 4))
        self.ax.set_title("Ping Response Time")
        self.ax.set_xlabel("Time (samples)")
        self.ax.set_ylabel("RTT (ms)")
        self.ax.grid(True)
        
        self.canvas = FigureCanvasTkAgg(self.fig, master=plot_frame)
        self.canvas.draw()
        self.canvas.get_tk_widget().pack(fill="both", expand=True)

    def setup_traceroute_tab(self):
        # Create frames
        control_frame = ttk.LabelFrame(self.traceroute_tab, text="Controls")
        control_frame.pack(fill="x", padx=10, pady=5)
        
        results_frame = ttk.LabelFrame(self.traceroute_tab, text="Traceroute Results")
        results_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Control widgets
        ttk.Label(control_frame, text="Target address:").grid(row=0, column=0, padx=5, pady=5)
        self.traceroute_address_entry = ttk.Entry(control_frame, width=30)
        self.traceroute_address_entry.grid(row=0, column=1, padx=5, pady=5)
        self.traceroute_address_entry.insert(0, "8.8.8.8")  # Default to Google DNS
        
        ttk.Label(control_frame, text="Max hops:").grid(row=0, column=2, padx=5, pady=5)
        self.max_hops_var = tk.IntVar(value=30)
        max_hops_spinner = ttk.Spinbox(control_frame, from_=1, to=64, increment=1, 
                                       textvariable=self.max_hops_var, width=5)
        max_hops_spinner.grid(row=0, column=3, padx=5, pady=5)
        
        self.run_traceroute_button = ttk.Button(control_frame, text="Run Traceroute", 
                                               command=self.run_traceroute)
        self.run_traceroute_button.grid(row=0, column=4, padx=5, pady=5)
        
        self.save_traceroute_button = ttk.Button(control_frame, text="Save Results", 
                                                command=self.save_traceroute_results)
        self.save_traceroute_button.grid(row=0, column=5, padx=5, pady=5)
        self.save_traceroute_button["state"] = "disabled"
        
        # Create visualization options
        viz_frame = ttk.Frame(control_frame)
        viz_frame.grid(row=1, column=0, columnspan=6, padx=5, pady=5, sticky="w")
        
        ttk.Label(viz_frame, text="View:").pack(side="left", padx=5)
        self.view_var = tk.StringVar(value="text")
        ttk.Radiobutton(viz_frame, text="Text", variable=self.view_var, value="text", 
                       command=self.switch_traceroute_view).pack(side="left", padx=5)
        ttk.Radiobutton(viz_frame, text="Table", variable=self.view_var, value="table", 
                       command=self.switch_traceroute_view).pack(side="left", padx=5)
        
        # Results area with notebook for different views
        self.results_notebook = ttk.Notebook(results_frame)
        self.results_notebook.pack(fill="both", expand=True)
        
        # Text view tab
        self.text_view_frame = ttk.Frame(self.results_notebook)
        self.results_notebook.add(self.text_view_frame, text="Text View")
        
        self.traceroute_output = scrolledtext.ScrolledText(self.text_view_frame, wrap=tk.WORD)
        self.traceroute_output.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Table view tab
        self.table_view_frame = ttk.Frame(self.results_notebook)
        self.results_notebook.add(self.table_view_frame, text="Table View")
        
        self.traceroute_tree = ttk.Treeview(self.table_view_frame, 
                                           columns=("Hop", "IP", "Hostname", "RTT1", "RTT2", "RTT3", "Avg RTT"))
        self.traceroute_tree.heading("#0", text="")
        self.traceroute_tree.column("#0", width=0, stretch=tk.NO)
        
        for col in ("Hop", "IP", "Hostname", "RTT1", "RTT2", "RTT3", "Avg RTT"):
            self.traceroute_tree.heading(col, text=col)
            width = 70 if col in ("Hop", "RTT1", "RTT2", "RTT3", "Avg RTT") else 150
            self.traceroute_tree.column(col, width=width)
        
        traceroute_scroll = ttk.Scrollbar(self.table_view_frame, orient="vertical", 
                                         command=self.traceroute_tree.yview)
        self.traceroute_tree.configure(yscrollcommand=traceroute_scroll.set)
        traceroute_scroll.pack(side="right", fill="y")
        self.traceroute_tree.pack(side="left", fill="both", expand=True)

    def switch_traceroute_view(self):
        view = self.view_var.get()
        if view == "text":
            self.results_notebook.select(0)  # Select text view tab
        else:
            self.results_notebook.select(1)  # Select table view tab

    def start_ping(self):
        address = self.address_entry.get().strip()
        if not address:
            messagebox.showerror("Error", "Please enter a valid address")
            return
        
        # Check if already monitoring this address
        if address in self.active_threads and self.active_threads[address].is_alive():
            messagebox.showinfo("Info", f"Already monitoring {address}")
            return
        
        # Initialize data storage for this address
        self.ping_data[address] = {
            "rtts": deque(maxlen=self.max_data_points),
            "times": deque(maxlen=self.max_data_points),
            "sent": 0,
            "received": 0,
            "status": "Starting..."
        }
        
        # Add to treeview
        if self.tree.exists(address):
            self.tree.item(address, values=(address, "Starting...", "N/A", "N/A", "0%"))
        else:
            self.tree.insert("", "end", address, values=(address, "Starting...", "N/A", "N/A", "0%"))
        
        # Start ping thread
        interval = self.interval_var.get()
        thread = threading.Thread(target=self.ping_address, 
                                 args=(address, interval), 
                                 daemon=True)
        self.active_threads[address] = thread
        thread.start()
        
        # Update UI
        self.update_buttons()

    def stop_ping(self):
        address = self.address_entry.get().strip()
        if address in self.ping_data:
            self.ping_data[address]["status"] = "Stopped"
            if self.tree.exists(address):
                self.tree.item(address, values=(address, "Stopped", "N/A", "N/A", "N/A"))
        
        # Update UI
        self.update_buttons()

    def ping_address(self, address, interval):
        start_time = time.time()
        sample_count = 0
        
        while self.running and self.ping_data[address]["status"] != "Stopped":
            try:
                # Determine the ping command based on the platform
                if platform.system().lower() == "windows":
                    cmd = ["ping", "-n", "1", "-w", "1000", address]
                else:  # Linux, macOS, etc.
                    cmd = ["ping", "-c", "1", "-W", "1", address]
                
                start = time.time()
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                end = time.time()
                
                self.ping_data[address]["sent"] += 1
                
                if result.returncode == 0:
                    rtt = self.parse_ping_result(result.stdout)
                    if rtt is None:  # Fallback to measured time if parsing fails
                        rtt = (end - start) * 1000
                    
                    self.ping_data[address]["received"] += 1
                    self.ping_data[address]["status"] = "Up"
                    
                    # Queue data for main thread processing
                    self.data_queue.put(("ping_data", address, rtt, sample_count))
                else:
                    # Ping failed
                    self.data_queue.put(("ping_timeout", address, None, sample_count))
                    self.ping_data[address]["status"] = "Down"
            
            except subprocess.TimeoutExpired:
                self.data_queue.put(("ping_timeout", address, None, sample_count))
                self.ping_data[address]["status"] = "Timeout"
            
            except Exception as e:
                self.data_queue.put(("ping_error", address, str(e), sample_count))
                self.ping_data[address]["status"] = f"Error: {str(e)}"
            
            sample_count += 1
            
            # Sleep for the specified interval
            time_elapsed = time.time() - start_time
            sleep_time = max(0, interval - (time.time() - start))
            time.sleep(sleep_time)

    def parse_ping_result(self, ping_output):
        try:
            # Different parsing logic for different platforms
            if platform.system().lower() == "windows":
                # Windows output format
                if "time=" in ping_output or "time<" in ping_output:
                    for line in ping_output.split('\n'):
                        if "time=" in line:
                            parts = line.split('time=')
                            rtt_str = parts[1].split('ms')[0].strip()
                            return float(rtt_str)
                        elif "time<" in line:
                            return 1.0  # Approximation for "time<1ms"
            else:
                # Unix-like output format
                if "time=" in ping_output:
                    for line in ping_output.split('\n'):
                        if "time=" in line:
                            parts = line.split('time=')
                            rtt_str = parts[1].split()[0].strip()
                            return float(rtt_str)
            
            return None
        except Exception:
            return None

    def run_traceroute(self):
        """Execute traceroute command and display results"""
        address = self.traceroute_address_entry.get().strip()
        if not address:
            messagebox.showerror("Error", "Please enter a valid address")
            return
        
        # Disable button during traceroute
        self.run_traceroute_button["state"] = "disabled"
        self.run_traceroute_button["text"] = "Running..."
        self.traceroute_output.delete(1.0, tk.END)
        self.traceroute_output.insert(tk.END, f"Running traceroute to {address}...\n\n")
        self.traceroute_tree.delete(*self.traceroute_tree.get_children())
        
        # Start traceroute in a thread
        thread = threading.Thread(target=self._run_traceroute_thread, 
                                 args=(address, self.max_hops_var.get()),
                                 daemon=True)
        thread.start()

    def _run_traceroute_thread(self, address, max_hops):
        """Execute traceroute in a separate thread"""
        try:
            # Determine the traceroute command based on the platform
            if platform.system().lower() == "windows":
                cmd = ["tracert", "-d", "-h", str(max_hops), address]
            else:  # Linux, macOS, etc.
                cmd = ["traceroute", "-n", "-m", str(max_hops), address]
            
            # Run the traceroute command
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            # Update UI with the results
            self.data_queue.put(("traceroute_complete", address, result.stdout, None))
            
        except subprocess.TimeoutExpired:
            self.data_queue.put(("traceroute_error", address, "Traceroute command timed out", None))
        except Exception as e:
            self.data_queue.put(("traceroute_error", address, f"Error: {str(e)}", None))

    def parse_traceroute_output(self, output, address):
        """Parse traceroute output and return structured data"""
        traces = []
        lines = output.split('\n')
        
        # Skip header lines
        start_line = 0
        for i, line in enumerate(lines):
            if "1 " in line:
                start_line = i
                break
        
        # Process each hop line
        for i in range(start_line, len(lines)):
            line = lines[i].strip()
            if not line:
                continue
                
            # Try to parse the line
            try:
                hop_data = {"hop_number": None, "ip": None, "hostname": None, "rtts": []}
                
                # Parse Windows tracert output
                if platform.system().lower() == "windows":
                    # Extract hop number
                    match = re.match(r'^\s*(\d+)', line)
                    if match:
                        hop_data["hop_number"] = int(match.group(1))
                    
                    # Look for timeouts
                    if "Request timed out" in line or "*" in line:
                        hop_data["ip"] = "*"
                        hop_data["hostname"] = "Request timed out"
                        traces.append(hop_data)
                        continue
                    
                    # Extract IP and RTTs
                    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if ip_match:
                        hop_data["ip"] = ip_match.group(1)
                        
                        # Try to extract hostname
                        parts = line.split(hop_data["ip"])
                        if len(parts) > 1 and "[" not in parts[0]:
                            hostname = parts[0].strip()
                            if hostname:
                                hop_data["hostname"] = hostname
                    
                    # Extract RTTs
                    rtt_matches = re.findall(r'(\d+)\s*ms', line)
                    for rtt in rtt_matches:
                        hop_data["rtts"].append(int(rtt))
                
                # Parse Unix traceroute output
                else:
                    parts = line.split()
                    if parts and parts[0].isdigit():
                        hop_data["hop_number"] = int(parts[0])
                        
                        if len(parts) > 1:
                            if "*" in parts[1]:
                                hop_data["ip"] = "*"
                                hop_data["hostname"] = "Request timed out"
                            else:
                                hop_data["ip"] = parts[1]
                                
                                # Extract RTTs
                                for i in range(2, min(5, len(parts))):
                                    try:
                                        rtt = float(parts[i])
                                        hop_data["rtts"].append(rtt)
                                    except ValueError:
                                        # Try to extract RTT from "123.456 ms" format
                                        rtt_match = re.search(r'(\d+\.\d+)', parts[i])
                                        if rtt_match:
                                            hop_data["rtts"].append(float(rtt_match.group(1)))
                
                if hop_data["hop_number"] is not None:
                    traces.append(hop_data)
                    
            except Exception as e:
                print(f"Error parsing traceroute line '{line}': {e}")
        
        # Store the traceroute data
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.traceroute_data[address] = {
            "timestamp": timestamp,
            "traces": traces,
            "raw_output": output
        }
        
        return traces

    def update_traceroute_display(self, address, output):
        """Update the traceroute display with parsed results"""
        # Update text output
        self.traceroute_output.delete(1.0, tk.END)
        self.traceroute_output.insert(tk.END, output)
        
        # Parse output and update table view
        traces = self.parse_traceroute_output(output, address)
        self.traceroute_tree.delete(*self.traceroute_tree.get_children())
        
        for trace in traces:
            hop_number = trace.get("hop_number", "")
            ip = trace.get("ip", "*")
            hostname = trace.get("hostname", "")
            
            # Get RTTs
            rtts = trace.get("rtts", [])
            rtt1 = f"{rtts[0]:.1f} ms" if len(rtts) > 0 and rtts[0] is not None else "*"
            rtt2 = f"{rtts[1]:.1f} ms" if len(rtts) > 1 and rtts[1] is not None else "*"
            rtt3 = f"{rtts[2]:.1f} ms" if len(rtts) > 2 and rtts[2] is not None else "*"
            
            # Calculate average RTT
            valid_rtts = [rtt for rtt in rtts if rtt is not None]
            avg_rtt = f"{sum(valid_rtts)/len(valid_rtts):.1f} ms" if valid_rtts else "*"
            
            # Add to treeview
            self.traceroute_tree.insert("", "end", values=(hop_number, ip, hostname, rtt1, rtt2, rtt3, avg_rtt))
        
        # Enable save button
        self.save_traceroute_button["state"] = "normal"
        
        # Re-enable run button
        self.run_traceroute_button["state"] = "normal"
        self.run_traceroute_button["text"] = "Run Traceroute"

    def save_traceroute_results(self):
        """Save traceroute results to a file"""
        address = self.traceroute_address_entry.get().strip()
        if address not in self.traceroute_data:
            messagebox.showerror("Error", "No traceroute data to save")
            return
        
        try:
            # Generate filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"traceroute_{address}_{timestamp}.txt"
            
            # Write to file
            with open(filename, "w") as f:
                f.write(f"Traceroute to {address}\n")
                f.write(f"Date: {self.traceroute_data[address]['timestamp']}\n\n")
                f.write(self.traceroute_data[address]['raw_output'])
            
            messagebox.showinfo("Success", f"Traceroute results saved to {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save results: {str(e)}")

    def process_queue(self):
        """Process data from the queue to update the UI safely"""
        while self.running:
            try:
                data = self.data_queue.get(timeout=0.5)
                if not data:
                    continue
                
                event_type, address, value, sample = data
                
                # Handle ping events
                if event_type == "ping_data":
                    # Valid ping response
                    self.ping_data[address]["rtts"].append(value)
                    self.ping_data[address]["times"].append(sample)
                    
                    # Update treeview
                    avg_rtt = sum(self.ping_data[address]["rtts"]) / len(self.ping_data[address]["rtts"])
                    loss_pct = ((self.ping_data[address]["sent"] - self.ping_data[address]["received"]) / 
                              max(1, self.ping_data[address]["sent"])) * 100
                    
                    if self.tree.exists(address):
                        self.tree.item(address, values=(
                            address,
                            self.ping_data[address]["status"],
                            f"{value:.1f}",
                            f"{avg_rtt:.1f}",
                            f"{loss_pct:.1f}%"
                        ))
                
                elif event_type in ["ping_timeout", "ping_error"]:
                    # Ping failed - update status only
                    loss_pct = ((self.ping_data[address]["sent"] - self.ping_data[address]["received"]) / 
                              max(1, self.ping_data[address]["sent"])) * 100
                    
                    if self.tree.exists(address):
                        avg_value = "N/A"
                        if self.ping_data[address]["rtts"]:
                            avg_value = f"{sum(self.ping_data[address]['rtts']) / len(self.ping_data[address]['rtts']):.1f}"
                            
                        self.tree.item(address, values=(
                            address,
                            self.ping_data[address]["status"],
                            "N/A",
                            avg_value,
                            f"{loss_pct:.1f}%"
                        ))
                
                # Handle traceroute events
                elif event_type == "traceroute_complete":
                    self.update_traceroute_display(address, value)
                    
                elif event_type == "traceroute_error":
                    self.traceroute_output.delete(1.0, tk.END)
                    self.traceroute_output.insert(tk.END, f"Error: {value}")
                    self.run_traceroute_button["state"] = "normal"
                    self.run_traceroute_button["text"] = "Run Traceroute"
                
                self.data_queue.task_done()
            
            except queue.Empty:
                pass
            except Exception as e:
                print(f"Error processing queue: {e}")

    def update_canvas(self):
        """Update the plot canvas with latest data"""
        if not self.running:
            return
            
        try:
            # Only update if we're on the ping tab
            if self.notebook.index(self.notebook.select()) == 0:
                # Clear the plot
                self.ax.clear()
                self.ax.set_title("Ping Response Time")
                self.ax.set_xlabel("Sample Number")
                self.ax.set_ylabel("RTT (ms)")
                self.ax.grid(True)
                
                # Plot data for each address with different colors
                colors = ['b', 'r', 'g', 'c', 'm', 'y', 'k']
                color_idx = 0
                
                for address, data in self.ping_data.items():
                    if data["rtts"] and data["times"]:
                        color = colors[color_idx % len(colors)]
                        self.ax.plot(list(data["times"]), list(data["rtts"]), 
                                    marker='o', linestyle='-', label=address, color=color)
                        color_idx += 1
                
                # Set y-axis limits with some padding
                all_rtts = [rtt for data in self.ping_data.values() for rtt in data["rtts"] if rtt is not None]
                if all_rtts:
                    self.ax.set_ylim(0, max(all_rtts) * 1.2)
                
                # Add legend if multiple addresses
                if len(self.ping_data) > 1:
                    self.ax.legend()
                    
                # Redraw the canvas
                self.canvas.draw()
        
        except Exception as e:
            print(f"Error updating plot: {e}")
        
        # Schedule the next update
        self.root.after(1000, self.update_canvas)

    def update_buttons(self):
        """Update button states based on current monitoring status"""
        address = self.address_entry.get().strip()
        is_monitoring = (address in self.active_threads and 
                       self.active_threads[address].is_alive() and 
                       self.ping_data.get(address, {}).get("status") != "Stopped")
        
        if is_monitoring:
            self.start_button["state"] = "disabled"
            self.stop_button["state"] = "normal"
        else:
            self.start_button["state"] = "normal"
            self.stop_button["state"] = "disabled"

    def on_closing(self):
        """Clean up when window is closed"""
        self.running = False
        # Wait for threads to terminate
        for thread in self.active_threads.values():
            if thread.is_alive():
                thread.join(0.1)
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkMonitor(root)
    root.mainloop()