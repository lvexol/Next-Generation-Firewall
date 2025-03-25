import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import webbrowser
from datetime import datetime
import base64
import requests
import json
from bs4 import BeautifulSoup
import re

class ThreatIntelligenceApp:
    def __init__(self, root):
        """Initialize the application"""
        self.root = root
        self.root.title("Threat Intelligence Dashboard")
        self.root.geometry("1200x800")
        
        # Define headers for HTTP requests
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        # Create variables
        self.auto_refresh = tk.BooleanVar(value=True)
        self.refresh_interval = tk.IntVar(value=60)  # minutes
        self.status_var = tk.StringVar(value="Ready")
        
        # Create main frame
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Create dashboard tab
        self.dashboard_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.dashboard_frame, text="Dashboard")
        
        # Create results tab
        self.results_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.results_frame, text="Results")
        
        # Create settings tab
        self.settings_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.settings_frame, text="Settings")
        
        # Create log tab
        self.log_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.log_frame, text="Log")
        self.log_text = scrolledtext.ScrolledText(self.log_frame, wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # Setup UI components
        self.setup_dashboard()
        self.setup_results()
        self.setup_settings()
        
        # Initialize the app
        self.initialize_app()
        
        # Initialize storage for logs and results
        self.stored_details = {}
        self.known_iocs = set()  # To track already seen IOCs
        
        # Set up the main frame
        self.main_frame = ttk.Frame(root)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create header
        self.header_frame = ttk.Frame(self.main_frame)
        self.header_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.title_label = ttk.Label(self.header_frame, text="Threat Intelligence Platform", font=("Arial", 18, "bold"))
        self.title_label.pack(side=tk.LEFT, padx=5)
        
        # Add auto-refresh toggle - enabled by default
        self.auto_refresh_check = ttk.Checkbutton(
            self.header_frame, 
            text="Auto-refresh (every 5 min)", 
            variable=self.auto_refresh,
            command=self.toggle_auto_refresh
        )
        self.auto_refresh_check.pack(side=tk.RIGHT, padx=5)
        
        # Add time range selector
        self.time_frame = ttk.Frame(self.header_frame)
        self.time_frame.pack(side=tk.RIGHT, padx=10)
        
        ttk.Label(self.time_frame, text="Time Range:").pack(side=tk.LEFT, padx=5)
        
        self.time_range = tk.StringVar(value="24 hours")
        time_ranges = ["24 hours", "48 hours", "7 days", "30 days"]
        self.time_combo = ttk.Combobox(self.time_frame, textvariable=self.time_range, values=time_ranges, width=10)
        self.time_combo.pack(side=tk.LEFT, padx=5)
        self.time_combo.bind("<<ComboboxSelected>>", lambda e: self.start_default_collection())
        
        # Create search section
        self.search_frame = ttk.LabelFrame(self.main_frame, text="Search Parameters")
        self.search_frame.pack(fill=tk.X, pady=5)
        
        # Search type selection
        self.search_type_frame = ttk.Frame(self.search_frame)
        self.search_type_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(self.search_type_frame, text="Search Type:").pack(side=tk.LEFT, padx=5)
        
        self.search_type = tk.StringVar(value="IP Address")
        search_types = ["IP Address", "Domain", "URL", "Hash", "CVE", "Keyword"]
        self.search_type_combo = ttk.Combobox(self.search_type_frame, textvariable=self.search_type, values=search_types, width=15)
        self.search_type_combo.pack(side=tk.LEFT, padx=5)
        
        # Search input
        self.search_input_frame = ttk.Frame(self.search_frame)
        self.search_input_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(self.search_input_frame, text="Search Query:").pack(side=tk.LEFT, padx=5)
        
        self.search_query = tk.StringVar()
        self.search_entry = ttk.Entry(self.search_input_frame, textvariable=self.search_query, width=50)
        self.search_entry.pack(side=tk.LEFT, padx=5)
        
        # Sources selection
        self.sources_frame = ttk.Frame(self.search_frame)
        self.sources_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(self.sources_frame, text="Sources:").pack(side=tk.LEFT, padx=5)
        
        self.source_abuseipdb = tk.BooleanVar(value=True)
        self.source_threatfox = tk.BooleanVar(value=True)
        self.source_urlhaus = tk.BooleanVar(value=True)
        self.source_phishtank = tk.BooleanVar(value=True)
        
        ttk.Checkbutton(self.sources_frame, text="AbuseIPDB", variable=self.source_abuseipdb).pack(side=tk.LEFT, padx=5)
        ttk.Checkbutton(self.sources_frame, text="ThreatFox", variable=self.source_threatfox).pack(side=tk.LEFT, padx=5)
        ttk.Checkbutton(self.sources_frame, text="URLhaus", variable=self.source_urlhaus).pack(side=tk.LEFT, padx=5)
        ttk.Checkbutton(self.sources_frame, text="PhishTank", variable=self.source_phishtank).pack(side=tk.LEFT, padx=5)
        
        # Search button
        self.button_frame = ttk.Frame(self.search_frame)
        self.button_frame.pack(fill=tk.X, padx=5, pady=10)
        
        self.search_button = ttk.Button(self.button_frame, text="Search", command=self.perform_search)
        self.search_button.pack(side=tk.RIGHT, padx=5)
        
        self.clear_button = ttk.Button(self.button_frame, text="Clear", command=self.clear_search)
        self.clear_button.pack(side=tk.RIGHT, padx=5)
        
        # Results section
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Results tab
        self.results_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.results_frame, text="Results")
        
        # Create a treeview for results
        self.results_tree = ttk.Treeview(self.results_frame, columns=("Source", "Type", "Result", "Timestamp"), show="headings")
        self.results_tree.heading("Source", text="Source")
        self.results_tree.heading("Type", text="Type")
        self.results_tree.heading("Result", text="Result")
        self.results_tree.heading("Timestamp", text="Timestamp")
        
        self.results_tree.column("Source", width=100)
        self.results_tree.column("Type", width=100)
        self.results_tree.column("Result", width=500)
        self.results_tree.column("Timestamp", width=150)
        
        self.results_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Add scrollbar to treeview
        self.results_scrollbar = ttk.Scrollbar(self.results_frame, orient=tk.VERTICAL, command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=self.results_scrollbar.set)
        self.results_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Details tab
        self.details_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.details_frame, text="Details")
        
        self.details_text = scrolledtext.ScrolledText(self.details_frame, wrap=tk.WORD)
        self.details_text.pack(fill=tk.BOTH, expand=True)
        
        # Visualization tab
        self.viz_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.viz_frame, text="Visualization")
        
        self.viz_label = ttk.Label(self.viz_frame, text="Visualization will be displayed here")
        self.viz_label.pack(pady=20)
        
        # Status bar
        self.status_frame = ttk.Frame(self.main_frame)
        self.status_frame.pack(fill=tk.X, side=tk.BOTTOM)
        
        self.status_label = ttk.Label(self.status_frame, textvariable=self.status_var, anchor=tk.W)
        self.status_label.pack(side=tk.LEFT, padx=5)
        
        # Bind events
        self.results_tree.bind("<Double-1>", self.show_details)
        
    def perform_search(self):
        query = self.search_query.get().strip()
        if not query:
            messagebox.showwarning("Input Error", "Please enter a search query")
            return
        
        # Clear previous results
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        self.details_text.delete(1.0, tk.END)
        self.status_var.set("Searching...")
        
        # Start search in a separate thread to keep UI responsive
        threading.Thread(target=self.search_thread, args=(query,), daemon=True).start()
    
    def search_thread(self, query):
        search_type = self.search_type.get()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Collect selected sources
        sources = []
        if self.source_abuseipdb.get() and search_type == "IP Address":
            sources.append("AbuseIPDB")
        if self.source_threatfox.get():
            sources.append("ThreatFox")
        if self.source_urlhaus.get():
            sources.append("URLhaus")
        if self.source_phishtank.get():
            sources.append("PhishTank")
        
        # Update UI in the main thread
        self.root.after(0, lambda: self.update_status(f"Searching {len(sources)} sources..."))
        
        # Perform actual searches
        for source in sources:
            # Simulate API delay
            import time
            time.sleep(0.5)
            
            # In a real implementation, this would call the respective APIs
            result, details = self.get_source_data(source, search_type, query)
            
            # Store details for later viewing
            self.store_details(source, search_type, query, details)
            
            # Add result to tree (in the main thread)
            self.root.after(0, lambda src=source, res=result: self.results_tree.insert("", tk.END, 
                values=(src, search_type, res, timestamp)))
        
        # Update status when done
        self.root.after(0, lambda: self.update_status(f"Search completed. Found results from {len(sources)} sources."))
    
    def store_details(self, source, search_type, query, details):
        """Store detailed results for later viewing"""
        if not hasattr(self, 'stored_details'):
            self.stored_details = {}
        
        key = f"{source}_{query}"
        self.stored_details[key] = details
    
    def get_source_data(self, source, search_type, query):
        """
        This method would contain the actual API calls to the different services.
        Returns a tuple of (summary, details)
        """
        if source == "AbuseIPDB":
            # For IP addresses only
            # In a real implementation, would call:
            # https://api.abuseipdb.com/api/v2/check?ipAddress={query}
            summary = f"IP reputation score: 87/100, reported 12 times"
            details = {
                "ip": query,
                "abuseConfidenceScore": 87,
                "totalReports": 12,
                "lastReportedAt": "2023-06-15",
                "countryCode": "US",
                "countryName": "United States",
                "usageType": "Data Center/Web Hosting",
                "isp": "Example ISP Inc.",
                "domain": "example.com",
                "categories": ["Web Scanning", "SSH Bruteforce"],
                "reports": [
                    {"reportedAt": "2023-06-15", "comment": "SSH brute force attempts", "categories": [22]},
                    {"reportedAt": "2023-06-10", "comment": "Web vulnerability scanning", "categories": [21]}
                ]
            }
            return summary, details
        
        elif source == "ThreatFox":
            # For various IOCs
            # In a real implementation, would call:
            # https://threatfox-api.abuse.ch/api/v1/ with POST data
            if search_type == "Hash":
                summary = f"Malware family: Emotet, first seen: 2023-05-12"
                details = {
                    "ioc": query,
                    "ioc_type": "md5_hash",
                    "threat_type": "malware",
                    "malware_family": "Emotet",
                    "first_seen": "2023-05-12",
                    "last_seen": "2023-06-20",
                    "confidence_level": 90,
                    "tags": ["botnet", "banking", "stealer"],
                    "reporter": "abuse.ch",
                    "reference": "https://threatfox.abuse.ch/ioc/" + query
                }
            elif search_type == "IP Address":
                summary = f"Associated with Emotet C2, first seen: 2023-05-12"
                details = {
                    "ioc": query,
                    "ioc_type": "ip_address",
                    "threat_type": "c2_server",
                    "malware_family": "Emotet",
                    "first_seen": "2023-05-12",
                    "last_seen": "2023-06-20",
                    "confidence_level": 90,
                    "tags": ["botnet", "c2"],
                    "reporter": "abuse.ch",
                    "reference": "https://threatfox.abuse.ch/browse/"
                }
            elif search_type == "Domain" or search_type == "URL":
                summary = f"Associated with Emotet C2, first seen: 2023-05-12"
                details = {
                    "ioc": query,
                    "ioc_type": "domain",
                    "threat_type": "c2_server",
                    "malware_family": "Emotet",
                    "first_seen": "2023-05-12",
                    "last_seen": "2023-06-20",
                    "confidence_level": 90,
                    "tags": ["botnet", "c2"],
                    "reporter": "abuse.ch",
                    "reference": "https://threatfox.abuse.ch/browse/"
                }
            else:
                summary = f"No direct matches found"
                details = {"error": "No data available for this indicator type"}
            
            return summary, details
        
        elif source == "URLhaus":
            # For URLs and domains
            # In a real implementation, would call:
            # https://urlhaus-api.abuse.ch/v1/url/ with POST data
            if search_type in ["URL", "Domain"]:
                summary = f"Status: online, malware type: Heodo, tags: exe, botnet"
                details = {
                    "url": query,
                    "status": "online",
                    "dateAdded": "2023-06-01",
                    "threat": "Heodo",
                    "tags": ["exe", "botnet"],
                    "reporter": "abuse.ch",
                    "payloads": [
                        {"url": "https://example.com/malware.exe", "filename": "malware.exe", "filesize": 245760, 
                         "filetype": "exe", "md5_hash": "a1b2c3d4e5f6g7h8i9j0", "sha256_hash": "1a2b3c..."}
                    ],
                    "reference": "https://urlhaus.abuse.ch/url/" + base64.b64encode(query.encode()).decode()
                }
            else:
                summary = f"No direct matches found"
                details = {"error": "No data available for this indicator type"}
            
            return summary, details
        
        elif source == "PhishTank":
            # For URLs to check if they're phishing sites
            # In a real implementation, would call:
            # http://checkurl.phishtank.com/checkurl/
            if search_type == "URL":
                summary = f"Verified phishing: Yes, targeting: PayPal"
                details = {
                    "url": query,
                    "in_database": True,
                    "verified": True,
                    "verified_at": "2023-06-02",
                    "target": "PayPal",
                    "verification_count": 5,
                    "reference": "https://www.phishtank.com/"
                }
            else:
                summary = f"No phishing data available for this indicator type"
                details = {"error": "PhishTank only accepts URLs"}
            
            return summary, details
        
        return f"No data available from {source} for {query}", {"error": "Service not available"}
    
    def show_details(self, event):
        item = self.results_tree.selection()[0]
        if not item:
            return
            
        values = self.results_tree.item(item, "values")
        source = values[0]
        query = self.search_query.get()
        
        self.details_text.delete(1.0, tk.END)
        
        # Display detailed information
        self.details_text.insert(tk.END, f"Source: {source}\n")
        self.details_text.insert(tk.END, f"Type: {values[1]}\n")
        self.details_text.insert(tk.END, f"Query: {query}\n")
        self.details_text.insert(tk.END, f"Timestamp: {values[3]}\n\n")
        self.details_text.insert(tk.END, "Detailed Results:\n")
        self.details_text.insert(tk.END, "-" * 50 + "\n\n")
        
        # Get stored details if available
        key = f"{source}_{query}"
        if hasattr(self, 'stored_details') and key in self.stored_details:
            details = self.stored_details[key]
            self.display_formatted_details(source, details)
        else:
            self.details_text.insert(tk.END, "No detailed information available.\n")
        
        # Add a button to open the source website
        self.add_view_button(source, query, values[1])
        
        # Add a button to add to log
        self.add_log_button(source, query, values[1])
        
        # Switch to details tab
        self.notebook.select(1)
    
    def display_formatted_details(self, source, details):
        """Format and display details based on the source"""
        if source == "AbuseIPDB":
            self.details_text.insert(tk.END, f"IP Address: {details['ip']}\n")
            self.details_text.insert(tk.END, f"Abuse Confidence Score: {details['abuseConfidenceScore']}%\n")
            self.details_text.insert(tk.END, f"Total Reports: {details['totalReports']}\n")
            self.details_text.insert(tk.END, f"Last Reported: {details['lastReportedAt']}\n")
            self.details_text.insert(tk.END, f"Country: {details['countryName']}\n")
            self.details_text.insert(tk.END, f"ISP: {details['isp']}\n")
            self.details_text.insert(tk.END, f"Usage Type: {details['usageType']}\n")
            self.details_text.insert(tk.END, f"Categories: {', '.join(details['categories'])}\n\n")
            
            self.details_text.insert(tk.END, "Recent Reports:\n")
            for report in details['reports']:
                self.details_text.insert(tk.END, f"- {report['reportedAt']}: {report['comment']}\n")
        
        elif source == "ThreatFox":
            self.details_text.insert(tk.END, f"IOC: {details['ioc']}\n")
            self.details_text.insert(tk.END, f"Date: {details.get('date', 'N/A')}\n")
            self.details_text.insert(tk.END, f"Malware: {details.get('malware', 'N/A')}\n")
            
            if 'tags' in details:
                self.details_text.insert(tk.END, f"Tags: {', '.join(details['tags'])}\n")
            
            self.details_text.insert(tk.END, f"Reporter: {details.get('reporter', 'N/A')}\n")
            
            # Add additional details if available
            if 'threat_type' in details:
                self.details_text.insert(tk.END, f"Threat Type: {details['threat_type']}\n")
            if 'confidence_level' in details:
                self.details_text.insert(tk.END, f"Confidence Level: {details['confidence_level']}%\n")
        
        elif source == "URLhaus":
            self.details_text.insert(tk.END, f"URL: {details['url']}\n")
            self.details_text.insert(tk.END, f"Status: {details['status']}\n")
            self.details_text.insert(tk.END, f"Date Added: {details['dateAdded']}\n")
            self.details_text.insert(tk.END, f"Threat: {details['threat']}\n")
            self.details_text.insert(tk.END, f"Tags: {', '.join(details['tags'])}\n")
            self.details_text.insert(tk.END, f"Reporter: {details['reporter']}\n\n")
            
            self.details_text.insert(tk.END, "Associated Payloads:\n")
            for payload in details['payloads']:
                self.details_text.insert(tk.END, f"- URL: {payload['url']}\n")
                self.details_text.insert(tk.END, f"  Filename: {payload['filename']}\n")
                self.details_text.insert(tk.END, f"  Size: {payload['filesize']} bytes\n")
                self.details_text.insert(tk.END, f"  Type: {payload['filetype']}\n")
                self.details_text.insert(tk.END, f"  MD5: {payload['md5_hash']}\n")
        
        elif source == "PhishTank":
            self.details_text.insert(tk.END, f"URL: {details['url']}\n")
            self.details_text.insert(tk.END, f"In Database: {details['in_database']}\n")
            self.details_text.insert(tk.END, f"Verified Phishing: {details['verified']}\n")
            self.details_text.insert(tk.END, f"Verification Date: {details['verified_at']}\n")
            self.details_text.insert(tk.END, f"Target: {details['target']}\n")
            self.details_text.insert(tk.END, f"Verified By: {details['verification_count']} users\n")
    
    def add_view_button(self, source, query, search_type):
        """Add a button to view the result on the original website"""
        # Remove any existing buttons
        for widget in self.details_frame.winfo_children():
            if isinstance(widget, ttk.Frame) and widget != self.details_text:
                widget.destroy()
        
        # Create button frame at the bottom of details
        button_frame = ttk.Frame(self.details_frame)
        button_frame.pack(fill=tk.X, side=tk.BOTTOM, pady=10)
        
        # Create the view button
        view_button = ttk.Button(
            button_frame, 
            text=f"View on {source}", 
            command=lambda: self.open_source_website(source, query, search_type)
        )
        view_button.pack(side=tk.RIGHT, padx=10)
    
    def add_log_button(self, source, query, search_type):
        """Add a button to add the result to the log"""
        # Find the button frame
        for widget in self.details_frame.winfo_children():
            if isinstance(widget, ttk.Frame) and widget != self.details_text:
                button_frame = widget
                break
        else:
            # If no button frame exists, create one
            button_frame = ttk.Frame(self.details_frame)
            button_frame.pack(fill=tk.X, side=tk.BOTTOM, pady=10)
        
        # Create the log button
        log_button = ttk.Button(
            button_frame, 
            text="Add to Log", 
            command=lambda: self.add_to_log(source, query, search_type)
        )
        log_button.pack(side=tk.LEFT, padx=10)
    
    def add_to_log(self, source, query, search_type):
        """Add the current result to the log"""
        # Create log tab if it doesn't exist
        if not hasattr(self, 'log_frame'):
            self.log_frame = ttk.Frame(self.notebook)
            self.notebook.add(self.log_frame, text="Log")
            
            self.log_text = scrolledtext.ScrolledText(self.log_frame, wrap=tk.WORD)
            self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # Get current timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Format log entry
        log_entry = f"[{timestamp}] {source} - {search_type}: {query}\n"
        
        # Get details if available
        key = f"{source}_{query}"
        if hasattr(self, 'stored_details') and key in self.stored_details:
            details = self.stored_details[key]
            
            if source == "AbuseIPDB":
                log_entry += f"  Abuse Score: {details['abuseConfidenceScore']}%, Reports: {details['totalReports']}\n"
            elif source == "ThreatFox":
                log_entry += f"  Malware: {details['malware_family']}, Type: {details['threat_type']}\n"
            elif source == "URLhaus":
                log_entry += f"  Status: {details['status']}, Threat: {details['threat']}\n"
            elif source == "PhishTank":
                log_entry += f"  Verified Phishing: {details['verified']}, Target: {details['target']}\n"
        
        log_entry += "-" * 50 + "\n"
        
        # Add to log
        self.log_text.insert(tk.END, log_entry)
        self.log_text.see(tk.END)  # Scroll to the end
        
        # Switch to log tab
        self.notebook.select(self.notebook.index(self.log_frame))
        
        # Show confirmation
        self.status_var.set(f"Added {query} from {source} to the log")
    
    def open_source_website(self, source, query, search_type):
        """Open the source website in the default browser"""
        if source == "AbuseIPDB":
            if search_type == "IP Address":
                url = f"https://www.abuseipdb.com/check/{query}"
            else:
                url = "https://www.abuseipdb.com/"
        
        elif source == "ThreatFox":
            # Check if we have a reference URL in stored details
            key = f"{source}_{query}"
            if hasattr(self, 'stored_details') and key in self.stored_details and 'reference' in self.stored_details[key]:
                url = self.stored_details[key]['reference']
            else:
                url = "https://threatfox.abuse.ch/browse/"
        
        elif source == "URLhaus":
            # Check if we have a reference URL in stored details
            key = f"{source}_{query}"
            if hasattr(self, 'stored_details') and key in self.stored_details and 'reference' in self.stored_details[key]:
                url = self.stored_details[key]['reference']
            else:
                url = "https://urlhaus.abuse.ch/browse/"
        
        elif source == "PhishTank":
            url = "https://www.phishtank.com/"
        
        else:
            # Try the new centralized hunting platform
            url = f"https://hunting.abuse.ch/?query={query}"
            
        # Open URL in default browser
        webbrowser.open(url)
    
    def clear_search(self):
        self.search_query.set("")
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        self.details_text.delete(1.0, tk.END)
        self.status_var.set("Ready")
    
    def update_status(self, message):
        self.status_var.set(message)
    
    def toggle_auto_refresh(self):
        """Toggle automatic refreshing of threat data"""
        if self.auto_refresh.get():
            self.status_var.set("Auto-refresh enabled. Monitoring for new threats...")
            # Start the auto-refresh cycle
            self.schedule_auto_refresh()
        else:
            self.status_var.set("Auto-refresh disabled.")
            # Cancel any scheduled auto-refresh
            if hasattr(self, 'refresh_job'):
                self.root.after_cancel(self.refresh_job)
    
    def initialize_app(self):
        """Initialize the application and start default collection"""
        # Create log tab if it doesn't exist
        if not hasattr(self, 'log_frame'):
            self.log_frame = ttk.Frame(self.notebook)
            self.notebook.add(self.log_frame, text="Log")
            
            self.log_text = scrolledtext.ScrolledText(self.log_frame, wrap=tk.WORD)
            self.log_text.pack(fill=tk.BOTH, expand=True)
            
            # Select the log tab by default
            self.notebook.select(self.notebook.index(self.log_frame))
        
        # Start default collection
        self.start_default_collection()
        
        # Start auto-refresh
        if self.auto_refresh.get():
            self.schedule_auto_refresh()
    
    def start_default_collection(self):
        """Start default threat intelligence collection"""
        self.log_message("Starting default threat collection...")
        self.status_var.set("Starting default threat collection...")
        
        # Collect ThreatFox IOCs
        self.collect_threatfox_iocs()
        
        self.status_var.set("Default collection complete")
        self.log_message("Default collection complete")
    
    def schedule_auto_refresh(self):
        """Schedule the next auto-refresh"""
        # Run auto-refresh every 5 minutes (300000 ms)
        self.refresh_job = self.root.after(300000, self.run_auto_refresh)
    
    def run_auto_refresh(self):
        """Run automatic refresh of threat data"""
        self.status_var.set("Auto-refreshing threat data...")
        
        # Start the auto-refresh in a separate thread
        threading.Thread(target=self.auto_refresh_thread, daemon=True).start()
        
        # Schedule the next refresh
        self.schedule_auto_refresh()
    
    def auto_refresh_thread(self):
        """Background thread for auto-refreshing threat data"""
        # Check ThreatFox for new IOCs
        new_iocs = self.check_threatfox_for_new_iocs()
        
        # Check URLhaus for new malicious URLs
        new_urls = self.check_urlhaus_for_new_urls()
        
        # Check PhishTank for new phishing sites
        new_phish = self.check_phishtank_for_new_phish()
        
        # Update the UI in the main thread
        total_new = len(new_iocs) + len(new_urls) + len(new_phish)
        if total_new > 0:
            self.root.after(0, lambda: self.update_status(f"Found {total_new} new threats during auto-refresh"))
            
            # Add all new findings to the log
            for ioc in new_iocs:
                self.root.after(0, lambda i=ioc: self.add_to_log_direct("ThreatFox", i, "IOC"))
            
            for url in new_urls:
                self.root.after(0, lambda u=url: self.add_to_log_direct("URLhaus", u, "URL"))
            
            for phish in new_phish:
                self.root.after(0, lambda p=phish: self.add_to_log_direct("PhishTank", p, "URL"))
        else:
            self.root.after(0, lambda: self.update_status("Auto-refresh completed. No new threats found."))
    
    def check_threatfox_for_new_iocs(self):
        """Check ThreatFox for new IP:port patterns"""
        try:
            url = "https://threatfox.abuse.ch/browse/"
            self.log_message(f"Downloading HTML from {url}...")
            
            # Define headers to avoid being blocked
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            
            response = requests.get(url, headers=headers)
            html_content = response.text
            
            # Save HTML to file for debugging
            with open("threatfox.html", "w", encoding="utf-8") as f:
                f.write(html_content)
            
            self.log_message("HTML downloaded and saved to threatfox.html")
            
            # Extract IP:port patterns using regex - specifically targeting patterns like 169.150.202.83:5552
            ip_port_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}\b'
            ip_ports = re.findall(ip_port_pattern, html_content)
            
            # Remove duplicates while preserving order
            unique_ip_ports = []
            for ip_port in ip_ports:
                if ip_port not in unique_ip_ports:
                    unique_ip_ports.append(ip_port)
            
            self.log_message(f"Found {len(unique_ip_ports)} unique IP:port patterns")
            
            # Log each IP:port
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            for ip_port in unique_ip_ports:
                log_entry = f"[{timestamp}] ThreatFox IOC: {ip_port}\n"
                
                # Add to log
                self.log_text.insert(tk.END, log_entry)
                self.log_text.see(tk.END)  # Scroll to the end
                
                # Add to results tree
                self.results_tree.insert("", 0, values=("ThreatFox", "IP:Port", ip_port, timestamp))
            
            return unique_ip_ports
        except Exception as e:
            error_msg = f"Error scraping ThreatFox: {str(e)}"
            self.log_message(error_msg)
            print(error_msg)
            return []
    
    def check_urlhaus_for_new_urls(self):
        """Check URLhaus for new malicious URLs"""
        # In a real implementation, this would call the URLhaus API
        # For now, we'll simulate finding new malicious URLs
        
        # Simulate API response with some malicious URLs
        mock_urls = [
            "http://malware-host.com/payload.exe",
            "http://another-bad-site.net/malware.zip",
            "https://evil-domain.org/dropper.doc"
        ]
        
        # Filter to only new URLs we haven't seen before
        new_urls = []
        for url in mock_urls:
            if url not in self.known_iocs:
                new_urls.append(url)
                self.known_iocs.add(url)
                
                # Store mock details for this URL
                details = {
                    "url": url,
                    "status": "online",
                    "dateAdded": datetime.now().strftime("%Y-%m-%d"),
                    "threat": "Heodo",
                    "tags": ["exe", "botnet"],
                    "reporter": "abuse.ch",
                    "payloads": [
                        {"url": url, "filename": url.split("/")[-1], "filesize": 245760, 
                         "filetype": "exe", "md5_hash": "a1b2c3d4e5f6g7h8i9j0", "sha256_hash": "1a2b3c..."}
                    ],
                    "reference": "https://urlhaus.abuse.ch/browse/"
                }
                
                key = f"URLhaus_{url}"
                self.stored_details[key] = details
        
        return new_urls
    
    def check_phishtank_for_new_phish(self):
        """Check PhishTank for new phishing sites"""
        # In a real implementation, this would call the PhishTank API
        # For now, we'll simulate finding new phishing sites
        
        # Simulate API response with some phishing URLs
        mock_phish = [
            "http://fake-bank-login.com",
            "http://paypal-secure-login.net",
            "https://amazon-account-verify.com"
        ]
        
        # Filter to only new phishing sites we haven't seen before
        new_phish = []
        for phish in mock_phish:
            if phish not in self.known_iocs:
                new_phish.append(phish)
                self.known_iocs.add(phish)
                
                # Store mock details for this phishing site
                details = {
                    "url": phish,
                    "in_database": True,
                    "verified": True,
                    "verified_at": datetime.now().strftime("%Y-%m-%d"),
                    "target": "PayPal" if "paypal" in phish else "Amazon" if "amazon" in phish else "Banking",
                    "verification_count": 5,
                    "reference": "https://www.phishtank.com/"
                }
                
                key = f"PhishTank_{phish}"
                self.stored_details[key] = details
        
        return new_phish
    
    def add_to_log_direct(self, source, query, search_type):
        """Add an item directly to the log without user interaction"""
        # Create log tab if it doesn't exist
        if not hasattr(self, 'log_frame'):
            self.log_frame = ttk.Frame(self.notebook)
            self.notebook.add(self.log_frame, text="Log")
            
            self.log_text = scrolledtext.ScrolledText(self.log_frame, wrap=tk.WORD)
            self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # Get current timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Format log entry
        log_entry = f"[{timestamp}] {source} - {search_type}: {query}\n"
        
        # Get details if available
        key = f"{source}_{query}"
        if key in self.stored_details:
            details = self.stored_details[key]
            
            if source == "ThreatFox":
                log_entry += f"  Date: {details.get('date', 'N/A')}\n"
                log_entry += f"  Malware: {details.get('malware', 'N/A')}\n"
                if 'tags' in details:
                    log_entry += f"  Tags: {', '.join(details['tags'])}\n"
                log_entry += f"  Reporter: {details.get('reporter', 'N/A')}\n"
            elif source == "URLhaus":
                log_entry += f"  Status: {details['status']}, Threat: {details['threat']}\n"
                log_entry += f"  Added: {details['dateAdded']}, Tags: {', '.join(details['tags'])}\n"
            elif source == "PhishTank":
                log_entry += f"  Verified Phishing: {details['verified']}, Target: {details['target']}\n"
                log_entry += f"  Verified at: {details['verified_at']}, Verifications: {details['verification_count']}\n"
        
        log_entry += "-" * 50 + "\n"
        
        # Add to log
        self.log_text.insert(tk.END, log_entry)
        self.log_text.see(tk.END)  # Scroll to the end
        
        # Add to results tree as well
        result_summary = ""
        if source == "ThreatFox":
            malware = self.stored_details[key].get('malware', '') if key in self.stored_details else ''
            result_summary = f"IOC: {query} - {malware}"
        elif source == "URLhaus":
            result_summary = f"Malicious URL: {query}"
        elif source == "PhishTank":
            result_summary = f"Phishing site: {query}"
            
        self.results_tree.insert("", 0, values=(source, search_type, result_summary, timestamp))

    def default_collection_thread(self):
        """Background thread for default threat collection"""
        time_range = self.time_range.get()
        
        # Update status
        self.root.after(0, lambda: self.update_status(f"Collecting threats from the last {time_range}..."))
        
        # Collect from ThreatFox by scraping the webpage
        self.root.after(0, lambda: self.update_status("Collecting IOCs from ThreatFox webpage..."))
        threatfox_iocs = self.scrape_threatfox()
        
        # Collect from URLhaus
        self.root.after(0, lambda: self.update_status("Collecting malicious URLs from URLhaus..."))
        urlhaus_urls = self.scrape_urlhaus_webpage()
        
        # Collect from PhishTank
        self.root.after(0, lambda: self.update_status("Collecting phishing sites from PhishTank..."))
        phishtank_urls = self.scrape_phishtank_webpage()
        
        # Process and display results
        total_threats = len(threatfox_iocs) + len(urlhaus_urls) + len(phishtank_urls)
        
        # Update UI in the main thread
        self.root.after(0, lambda: self.update_status(
            f"Collection complete. Found {total_threats} threats."
        ))
        
        # Add all findings to the log directly in the main thread
        for ioc_data in threatfox_iocs:
            self.root.after(0, lambda i=ioc_data: self.add_ioc_to_log("ThreatFox", i))
        
        for url_data in urlhaus_urls:
            self.root.after(0, lambda u=url_data: self.add_url_to_log("URLhaus", u))
        
        for phish_data in phishtank_urls:
            self.root.after(0, lambda p=phish_data: self.add_url_to_log("PhishTank", p))
    
    def scrape_threatfox(self):
        """Scrape ThreatFox website for IP:port patterns"""
        try:
            url = "https://threatfox.abuse.ch/browse/"
            self.log_message(f"Downloading HTML from {url}...")
            
            # Define headers to avoid being blocked
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            
            response = requests.get(url, headers=headers)
            html_content = response.text
            
            # Save HTML to file for debugging
            with open("threatfox.html", "w", encoding="utf-8") as f:
                f.write(html_content)
            
            self.log_message("HTML downloaded and saved to threatfox.html")
            
            # Extract IP:port patterns using regex
            ip_port_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+\b'
            ip_ports = re.findall(ip_port_pattern, html_content)
            
            self.log_message(f"Found {len(ip_ports)} IP:port patterns")
            
            # Log each IP:port
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            for ip_port in ip_ports:
                log_entry = f"[{timestamp}] ThreatFox IOC: {ip_port}\n"
                
                # Add to log
                self.log_text.insert(tk.END, log_entry)
                self.log_text.see(tk.END)  # Scroll to the end
                
                # Add to results tree
                self.results_tree.insert("", 0, values=("ThreatFox", "IP:Port", ip_port, timestamp))
            
            return ip_ports
        except Exception as e:
            error_msg = f"Error scraping ThreatFox: {str(e)}"
            self.log_message(error_msg)
            print(error_msg)
            return []
    
    def scrape_urlhaus_webpage(self):
        """Scrape the URLhaus webpage to collect malicious URLs"""
        try:
            # Get the URLhaus browse page
            url = "https://urlhaus.abuse.ch/browse/"
            response = requests.get(url)
            
            if response.status_code != 200:
                self.root.after(0, lambda: self.update_status(f"Error accessing URLhaus: HTTP {response.status_code}"))
                return []
            
            # Parse the HTML
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find the table with URLs
            table = soup.find('table', {'class': 'table-striped'})
            if not table:
                self.root.after(0, lambda: self.update_status("Could not find URL table on URLhaus"))
                return []
            
            # Extract URLs from the table
            urls = []
            rows = table.find_all('tr')
            
            # Skip header row
            for row in rows[1:]:
                cells = row.find_all('td')
                if len(cells) >= 4:  # Ensure we have enough cells
                    date_added = cells[0].text.strip()
                    url_text = cells[1].text.strip()
                    status = cells[2].text.strip()
                    tags = cells[3].text.strip().split()
                    
                    url_data = {
                        "dateAdded": date_added,
                        "url": url_text,
                        "status": status,
                        "tags": tags
                    }
                    
                    urls.append(url_data)
            
            self.root.after(0, lambda: self.update_status(f"Found {len(urls)} malicious URLs on URLhaus"))
            return urls
            
        except Exception as e:
            self.root.after(0, lambda: self.update_status(f"Error scraping URLhaus: {str(e)}"))
            return []
    
    def scrape_phishtank_webpage(self):
        """Scrape the PhishTank webpage to collect phishing sites"""
        try:
            # Get the PhishTank browse page
            url = "https://phishtank.org/phish_search.php?verified=u&active=y"
            response = requests.get(url)
            
            if response.status_code != 200:
                self.root.after(0, lambda: self.update_status(f"Error accessing PhishTank: HTTP {response.status_code}"))
                return []
            
            # Parse the HTML
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find the table with phishing sites
            table = soup.find('table', {'class': 'data'})
            if not table:
                self.root.after(0, lambda: self.update_status("Could not find phishing table on PhishTank"))
                return []
            
            # Extract phishing sites from the table
            phishing_sites = []
            rows = table.find_all('tr')
            
            # Skip header row
            for row in rows[1:]:
                cells = row.find_all('td')
                if len(cells) >= 6:  # Ensure we have enough cells
                    phish_id = cells[0].text.strip()
                    url_text = cells[1].text.strip()
                    submitted = cells[2].text.strip()
                    verified = cells[3].text.strip()
                    target = cells[5].text.strip()
                    
                    phish_data = {
                        "id": phish_id,
                        "url": url_text,
                        "submitted": submitted,
                        "verified": verified == "Yes",
                        "target": target
                    }
                    
                    phishing_sites.append(phish_data)
            
            self.root.after(0, lambda: self.update_status(f"Found {len(phishing_sites)} phishing sites on PhishTank"))
            return phishing_sites
            
        except Exception as e:
            self.root.after(0, lambda: self.update_status(f"Error scraping PhishTank: {str(e)}"))
            return []
    
    def add_ioc_to_log(self, source, ioc_data):
        """Add an IOC directly to the log"""
        # Get current timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Format log entry
        log_entry = f"[{timestamp}] {source} - IOC: {ioc_data['ioc']}\n"
        log_entry += f"  Date: {ioc_data['date']}\n"
        log_entry += f"  Malware: {ioc_data['malware']}\n"
        log_entry += "-" * 50 + "\n"
        
        # Add to log
        self.log_text.insert(tk.END, log_entry)
        self.log_text.see(tk.END)  # Scroll to the end
        
        # Add to results tree
        self.results_tree.insert("", 0, values=(source, "IOC", f"IOC: {ioc_data['ioc']} - {ioc_data['malware']}", timestamp))
    
    def add_url_to_log(self, source, url_data):
        """Add a URL directly to the log"""
        # Get current timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Format log entry
        log_entry = f"[{timestamp}] {source} - URL: {url_data['url']}\n"
        
        if source == "URLhaus":
            log_entry += f"  Date Added: {url_data['dateAdded']}\n"
            log_entry += f"  Status: {url_data['status']}\n"
            log_entry += f"  Tags: {', '.join(url_data['tags'])}\n"
        elif source == "PhishTank":
            log_entry += f"  Submitted: {url_data['submitted']}\n"
            log_entry += f"  Verified: {'Yes' if url_data['verified'] else 'No'}\n"
            log_entry += f"  Target: {url_data['target']}\n"
        
        log_entry += "-" * 50 + "\n"
        
        # Add to log
        self.log_text.insert(tk.END, log_entry)
        self.log_text.see(tk.END)  # Scroll to the end
        
        # Add to results tree
        result_summary = f"URL: {url_data['url']}"
        if source == "URLhaus":
            result_summary += f" - {url_data['status']}"
        elif source == "PhishTank":
            result_summary += f" - {url_data['target']}"
            
        self.results_tree.insert("", 0, values=(source, "URL", result_summary, timestamp))

    def log_message(self, message):
        """Add a message to the log"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        
        # Make sure log_text exists
        if hasattr(self, 'log_text'):
            self.log_text.insert(tk.END, log_entry)
            self.log_text.see(tk.END)  # Scroll to the end
        else:
            print(log_entry)  # Fallback to console if log_text doesn't exist yet

    def setup_dashboard(self):
        """Setup the dashboard tab"""
        # Create frame for controls
        controls_frame = ttk.Frame(self.dashboard_frame, padding="10")
        controls_frame.pack(fill=tk.X)
        
        # Create buttons for data collection
        ttk.Button(controls_frame, text="Collect ThreatFox IOCs", 
                   command=self.collect_threatfox_iocs).pack(side=tk.LEFT, padx=5)
        
        # Create frame for dashboard content
        content_frame = ttk.Frame(self.dashboard_frame, padding="10")
        content_frame.pack(fill=tk.BOTH, expand=True)
        
        # Add status bar
        status_frame = ttk.Frame(self.dashboard_frame)
        status_frame.pack(fill=tk.X, side=tk.BOTTOM)
        ttk.Label(status_frame, textvariable=self.status_var).pack(side=tk.LEFT, padx=5)
        
        # Add some placeholder content
        ttk.Label(content_frame, text="Threat Intelligence Dashboard", 
                  font=("Arial", 16)).pack(pady=20)

    def setup_results(self):
        """Setup the results tab"""
        # Create a treeview for results
        columns = ("Source", "Type", "Details", "Timestamp")
        self.results_tree = ttk.Treeview(self.results_frame, columns=columns, show="headings")
        
        # Define column headings
        for col in columns:
            self.results_tree.heading(col, text=col)
            self.results_tree.column(col, width=100)
        
        # Set the Details column to be wider
        self.results_tree.column("Details", width=400)
        
        # Add scrollbars
        y_scrollbar = ttk.Scrollbar(self.results_frame, orient=tk.VERTICAL, command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=y_scrollbar.set)
        
        # Pack everything
        self.results_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        y_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def setup_settings(self):
        """Setup the settings tab"""
        settings_frame = ttk.Frame(self.settings_frame, padding="20")
        settings_frame.pack(fill=tk.BOTH, expand=True)
        
        # Auto-refresh settings
        ttk.Checkbutton(settings_frame, text="Auto-refresh data", 
                       variable=self.auto_refresh).grid(row=0, column=0, sticky=tk.W, pady=5)
        
        ttk.Label(settings_frame, text="Refresh interval (minutes):").grid(row=1, column=0, sticky=tk.W, pady=5)
        ttk.Spinbox(settings_frame, from_=1, to=1440, textvariable=self.refresh_interval, 
                   width=5).grid(row=1, column=1, sticky=tk.W, pady=5)
        
        # Save button
        ttk.Button(settings_frame, text="Save Settings", 
                  command=self.save_settings).grid(row=2, column=0, pady=20)

    def save_settings(self):
        """Save the current settings"""
        self.log_message("Settings saved")
        # In a real app, you might save to a config file here

    def collect_threatfox_iocs(self):
        """Collect IOCs from ThreatFox"""
        self.log_message("Starting ThreatFox IOC collection...")
        self.status_var.set("Collecting ThreatFox IOCs...")
        
        try:
            url = "https://threatfox.abuse.ch/browse/"
            self.log_message(f"Downloading HTML from {url}...")
            
            # Define headers to avoid being blocked
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            
            response = requests.get(url, headers=headers)
            html_content = response.text
            
            # Extract IP:port patterns using regex - specifically targeting patterns like 169.150.202.83:5552
            ip_port_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}\b'
            ip_ports = re.findall(ip_port_pattern, html_content)
            
            # Remove duplicates while preserving order
            unique_ip_ports = []
            for ip_port in ip_ports:
                if ip_port not in unique_ip_ports:
                    unique_ip_ports.append(ip_port)
            
            self.log_message(f"Found {len(unique_ip_ports)} unique IP:port patterns")
            
            # Log each IP:port
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            for ip_port in unique_ip_ports:
                log_entry = f"[{timestamp}] ThreatFox IOC: {ip_port}\n"
                
                # Add to log
                self.log_text.insert(tk.END, log_entry)
                self.log_text.see(tk.END)  # Scroll to the end
                
                # Add to results tree
                self.results_tree.insert("", 0, values=("ThreatFox", "IP:Port", ip_port, timestamp))
            
            self.status_var.set(f"Found {len(unique_ip_ports)} IP:port IOCs")
            return unique_ip_ports
        except Exception as e:
            error_msg = f"Error collecting ThreatFox IOCs: {str(e)}"
            self.log_message(error_msg)
            self.status_var.set("Error collecting ThreatFox IOCs")
            print(error_msg)
            return []

def main():
    root = tk.Tk()
    app = ThreatIntelligenceApp(root)
    
    # Initialize the app after a short delay to ensure the UI is fully loaded
    root.after(100, app.initialize_app)
    
    root.mainloop()

if __name__ == "__main__":
    main()
