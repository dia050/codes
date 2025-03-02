import tkinter as tk
from tkinter import messagebox, filedialog, scrolledtext
import requests
import whois
import threading
import os

# Load API key from environment variable
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

# Function to fetch IP Geolocation data
def get_ip_info():
    ip_address = ip_entry.get().strip()
    if not ip_address:
        messagebox.showwarning("Input Error", "Please enter an IP address.")
        return
    
    def fetch_data():
        try:
            # Geolocation API
            geo_response = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=5)
            geo_data = geo_response.json()
            
            if geo_data.get("status") == "fail":
                messagebox.showerror("Error", "Invalid IP address or data not found.")
                return
            
            # VPN & Proxy Detection API
            vpn_response = requests.get(f"https://ipwhois.app/json/{ip_address}", timeout=5)
            vpn_data = vpn_response.json()
            
            # IP Reputation Check API (if API key is set)
            reputation_score = "N/A"
            if ABUSEIPDB_API_KEY:
                reputation_response = requests.get(
                    f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip_address}",
                    headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
                    timeout=5
                )
                reputation_data = reputation_response.json()
                reputation_score = reputation_data.get("data", {}).get("abuseConfidenceScore", "N/A")
            
            result_text = (
                f"IP Address: {ip_address}\n"
                f"Country: {geo_data['country']} ({geo_data['countryCode']})\n"
                f"Region: {geo_data['regionName']}\n"
                f"City: {geo_data['city']}\n"
                f"ZIP Code: {geo_data['zip']}\n"
                f"Latitude: {geo_data['lat']}, Longitude: {geo_data['lon']}\n"
                f"ISP: {geo_data['isp']}\n"
                f"Org: {geo_data['org']}\n"
                f"VPN/Proxy Detected: {'Yes' if vpn_data.get('proxy', False) else 'No'}\n"
                f"IP Reputation Score: {reputation_score}%\n"
            )
            
            result_text_widget.config(state=tk.NORMAL)
            result_text_widget.delete(1.0, tk.END)
            result_text_widget.insert(tk.END, result_text)
            result_text_widget.config(state=tk.DISABLED)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to fetch data: {e}")
    
    threading.Thread(target=fetch_data, daemon=True).start()

# Function to perform WHOIS lookup
def get_whois_info():
    ip_address = ip_entry.get().strip()
    if not ip_address:
        messagebox.showwarning("Input Error", "Please enter an IP or domain.")
        return
    
    def fetch_whois():
        try:
            domain_info = whois.whois(ip_address)
            whois_text = (
                f"Domain Name: {domain_info.domain_name}\n"
                f"Registrar: {domain_info.registrar}\n"
                f"Creation Date: {domain_info.creation_date}\n"
                f"Expiration Date: {domain_info.expiration_date}\n"
                f"Name Servers: {', '.join(domain_info.name_servers) if domain_info.name_servers else 'N/A'}\n"
            )
            
            whois_text_widget.config(state=tk.NORMAL)
            whois_text_widget.delete(1.0, tk.END)
            whois_text_widget.insert(tk.END, whois_text)
            whois_text_widget.config(state=tk.DISABLED)
        except Exception as e:
            messagebox.showerror("Error", f"WHOIS lookup failed: {e}")
    
    threading.Thread(target=fetch_whois, daemon=True).start()

# Function to export results to a file
def export_results():
    data = result_text_widget.get(1.0, tk.END).strip() + "\n\n" + whois_text_widget.get(1.0, tk.END).strip()
    if not data.strip():
        messagebox.showwarning("Export Error", "No data to export.")
        return
    
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
    if file_path:
        with open(file_path, "w") as file:
            file.write(data)
        messagebox.showinfo("Success", "Results exported successfully.")

# GUI Setup
root = tk.Tk()
root.title("Advanced IP Tracer GUI Tool")
root.geometry("700x600")

# Input Field
tk.Label(root, text="Enter IP Address or Domain:", font=("Arial", 12)).pack(pady=5)
ip_entry = tk.Entry(root, font=("Arial", 12), width=40)
ip_entry.pack(pady=5)

# Buttons
tk.Button(root, text="Get IP Info", font=("Arial", 12), command=get_ip_info).pack(pady=5)
tk.Button(root, text="Perform WHOIS Lookup", font=("Arial", 12), command=get_whois_info).pack(pady=5)
tk.Button(root, text="Export Results", font=("Arial", 12), command=export_results).pack(pady=5)

# Results Display
result_text_widget = scrolledtext.ScrolledText(root, font=("Arial", 10), width=80, height=10, wrap=tk.WORD, state=tk.DISABLED)
result_text_widget.pack(pady=5)

whois_text_widget = scrolledtext.ScrolledText(root, font=("Arial", 10), width=80, height=10, wrap=tk.WORD, state=tk.DISABLED)
whois_text_widget.pack(pady=5)

# Run GUI
root.mainloop()