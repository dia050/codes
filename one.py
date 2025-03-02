import tkinter as tk
from tkinter import messagebox
from email import message_from_string
import re

class EmailForensicApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Email Forensics Tool")
        self.root.geometry("600x400")

        # Email Header Label
        self.header_label = tk.Label(root, text="Enter Raw Email Header:")
        self.header_label.pack(pady=10)

        # Textbox for email header input
        self.header_input = tk.Text(root, width=70, height=10)
        self.header_input.pack(pady=10)

        # Analyze Button
        self.analyze_button = tk.Button(root, text="Analyze Email Header", command=self.analyze_email)
        self.analyze_button.pack(pady=10)

        # Results label
        self.result_label = tk.Label(root, text="Analysis Results:")
        self.result_label.pack(pady=10)

        # Textbox to display analysis results
        self.result_area = tk.Text(root, width=70, height=10)
        self.result_area.pack(pady=10)

    def analyze_email(self):
        raw_email = self.header_input.get("1.0", tk.END).strip()
        if not raw_email:
            messagebox.showwarning("Input Error", "Please enter a raw email header.")
            return

        try:
            # Parse the email header
            msg = message_from_string(raw_email)
            
            # Extract key header fields
            subject = msg.get("Subject", "No subject found")
            sender = msg.get("From", "Unknown sender")
            recipient = msg.get("To", "Unknown recipient")
            date_sent = msg.get("Date", "Unknown date")
            received = msg.get_all("Received") or []

            # Check for spoofing
            spoofing_warning = self.check_for_spoofing(sender, received)

            # Format the results
            received_headers = "\n".join(received) if received else "No received headers found."
            analysis_result = (
                f"Subject: {subject}\nSender: {sender}\nRecipient: {recipient}\nDate Sent: {date_sent}\n\n"
                f"Received Headers:\n{received_headers}\n\n"
                f"{spoofing_warning}"
            )

            # Display the results
            self.result_area.delete("1.0", tk.END)
            self.result_area.insert(tk.END, analysis_result)

        except Exception as e:
            messagebox.showerror("Parsing Error", f"Error parsing the email header:\n{e}")

    def check_for_spoofing(self, sender, received_headers):
        if not received_headers:
            return "No received headers available to check for spoofing."

        sender_domain = sender.split('@')[-1] if sender and '@' in sender else ""
        spoofing_warning = "No spoofing detected."

        for received in received_headers:
            ips = re.findall(r"\d+\.\d+\.\d+\.\d+", received)
            if sender_domain and all(sender_domain not in r for r in received_headers):
                return f"Warning: Potential Spoofing Detected. None of the received headers match sender domain ({sender_domain})."
    
        return spoofing_warning

if __name__ == "__main__":
    root = tk.Tk()
    app = EmailForensicApp(root)
    root.mainloop()
