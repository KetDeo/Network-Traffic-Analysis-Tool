import tkinter as tk
from tkinter import ttk, messagebox
from scapy.all import sniff
import pandas as pd
from scapy.layers.inet import IP, TCP, UDP, ICMP
import matplotlib.pyplot as plt
import signal
import sys
from datetime import datetime
import threading

captured_packets = []
stop_sniffing = False

def build_filter(protocol):
    if protocol == "tcp":
        return "tcp"
    elif protocol == "udp":
        return "udp"
    elif protocol == "icmp":
        return "icmp"
    else:
        return ""


def capture_packet(packet):
    if stop_sniffing:  
        return False
    
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = None
        src_port = None
        dst_port = None
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')  
        
        if TCP in packet:
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        elif ICMP in packet:
            protocol = "ICMP"
        else:
            protocol = "Other"
        
       
        captured_packets.append(packet)

        
        result_text.insert(tk.END, f"Packet Captured at {timestamp}:\n")
        result_text.insert(tk.END, f"Source IP: {ip_src}\n")
        result_text.insert(tk.END, f"Destination IP: {ip_dst}\n")
        result_text.insert(tk.END, f"Protocol: {protocol}\n")
        if src_port:
            result_text.insert(tk.END, f"Source Port: {src_port}\n")
        if dst_port:
            result_text.insert(tk.END, f"Destination Port: {dst_port}\n")
        result_text.insert(tk.END, "\n")
        result_text.see(tk.END)

    return True  


def analyze_packets(packets):
    packet_data = []

    for packet in packets:
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            protocol = packet[IP].proto
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')  

            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                protocol_name = "TCP"
            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                protocol_name = "UDP"
            elif ICMP in packet:
                src_port = None
                dst_port = None
                protocol_name = "ICMP"
            else:
                src_port = None
                dst_port = None
                protocol_name = str(protocol)

            
            malicious_flag = 0
            if src_port and dst_port and dst_port in range(1, 1024):  
                malicious_flag = 1

            packet_data.append({
                'Timestamp': timestamp,
                'Source IP': ip_src,
                'Destination IP': ip_dst,
                'Protocol': protocol_name,
                'Source Port': src_port,
                'Destination Port': dst_port,
                'Malicious': malicious_flag  
            })

    return pd.DataFrame(packet_data)


def save_to_file(packet_df, filename="captured_packets.csv"):
    packet_df.to_csv(filename, mode='a', header=not pd.io.common.file_exists(filename), index=False)
    messagebox.showinfo("Save to File", f"Saved captured packet data to {filename}")


def visualize_traffic(packet_df):
  
    protocol_counts = packet_df['Protocol'].value_counts()
    plt.figure(figsize=(10, 6))
    protocol_counts.plot(kind='barh', color='skyblue')
    plt.title("Protocol Distribution")
    plt.xlabel("Number of Packets")
    plt.ylabel("Protocol")
    plt.show()

  
    top_source_ips = packet_df['Source IP'].value_counts().head(10)  # Display top 10 source IPs
    plt.figure(figsize=(10, 6))
    top_source_ips.plot(kind='barh', color='lightgreen')
    plt.title("Top Source IPs")
    plt.xlabel("Number of Packets")
    plt.ylabel("Source IP")
    plt.show()


def detect_anomalies(packet_df):
    potential_threats = []

  
    port_scan_threshold = 10
    ip_grouped = packet_df.groupby('Source IP')['Destination Port'].nunique()

    for ip, port_count in ip_grouped.items():
        if port_count > port_scan_threshold:
            potential_threats.append(f"Potential port scan detected from {ip} to {port_count} different ports.")

    return potential_threats


def signal_handler(sig, frame):
    global stop_sniffing
    stop_sniffing = True
    root.quit()


def start_capture():
    global captured_packets, stop_sniffing
    captured_packets = []
    stop_sniffing = False
    
    protocol_filter = protocol_var.get().strip().lower()
    iface_filter = iface_var.get().strip()
    
    filter_str = build_filter(protocol_filter)
    
    result_text.insert(tk.END, f"Starting capture on interface '{iface_filter}' with filter '{filter_str}'...\n")
    result_text.insert(tk.END, "Press 'Stop Capture' to stop.\n\n")
    result_text.see(tk.END)
    
    sniff(prn=capture_packet, filter=filter_str, iface=iface_filter if iface_filter else None, stop_filter=lambda x: stop_sniffing)


def stop_capture():
    global stop_sniffing
    stop_sniffing = True


def process_packets():
    if not captured_packets:
        messagebox.showinfo("No Data", "No packets captured to process.")
        return

    packet_df = analyze_packets(captured_packets)

    save_to_file(packet_df)
    
    threats = detect_anomalies(packet_df)
    if threats:
        result_text.insert(tk.END, "Potential threats detected:\n")
        for threat in threats:
            result_text.insert(tk.END, threat + "\n")
    else:
        result_text.insert(tk.END, "No threats detected.\n")
    
    visualize_traffic(packet_df)


def exit_application():
    stop_capture()  
    root.quit()    
    sys.exit(0)     


root = tk.Tk()
root.title("Network Traffic Analyzer")


tk.Label(root, text="Protocol Filter:").grid(row=0, column=0, padx=10, pady=5, sticky='w')
protocol_var = tk.StringVar(value="none")
protocol_entry = ttk.Combobox(root, textvariable=protocol_var)
protocol_entry['values'] = ('tcp', 'udp', 'icmp', 'none')
protocol_entry.grid(row=0, column=1, padx=10, pady=5)


tk.Label(root, text="Network Interface:").grid(row=1, column=0, padx=10, pady=5, sticky='w')
iface_var = tk.StringVar(value="eth0")
iface_entry = ttk.Combobox(root, textvariable=iface_var)
iface_entry['values'] = ('eth0', 'lo', 'wlan0', 'any')
iface_entry.grid(row=1, column=1, padx=10, pady=5)


start_button = tk.Button(root, text="Start Capture", command=lambda: threading.Thread(target=start_capture).start())
start_button.grid(row=2, column=0, padx=10, pady=10)

stop_button = tk.Button(root, text="Stop Capture", command=stop_capture)
stop_button.grid(row=2, column=1, padx=10, pady=10)

analyze_button = tk.Button(root, text="Analyze and Visualize", command=process_packets)
analyze_button.grid(row=3, column=0, columnspan=2, padx=10, pady=10)

exit_button = tk.Button(root, text="Exit", command=exit_application)
exit_button.grid(row=4, column=0, columnspan=2, padx=10, pady=10)


result_text = tk.Text(root, height=15, width=80)
result_text.grid(row=5, column=0, columnspan=2, padx=10, pady=10)


signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


root.mainloop()
