import nmap
import json
from concurrent.futures import ThreadPoolExecutor
from fpdf import FPDF
import os
import nmap
from typing import Dict, Any
import nmap

def scan_host(ip):
    scanner = nmap.PortScanner()
    scanner.scan(ip, arguments='-T4 -F')  # fast scan, fewer ports
    if ip not in scanner.all_hosts():
        return {"ip": ip, "state": "down", "protocols": {}}

    host_data = {
        "ip": ip,
        "state": scanner[ip].state(),  # "up" / "down"
        "protocols": {}
    }

    for proto in scanner[ip].all_protocols():   # e.g. "tcp", "udp"
        proto_dict = scanner[ip][proto]        # dict of {port: {state, name, ...}}
        ports = []
        for port, portdata in proto_dict.items():
            ports.append({
                "port": port,
                "state": portdata.get("state", ""),
                "service": portdata.get("name", "")
            })
        ports.sort(key=lambda x: x["port"])
        host_data["protocols"][proto] = ports

    return host_data

def scan_network(subnet):
    hosts = [f"{subnet}.{i}" for i in range(1, 255)]
    results = {}
    with ThreadPoolExecutor(max_workers=50) as executor:
        for result in executor.map(scan_host, hosts):
            if result:
                results.update(result)
    return results

def export_to_json(data, filename="results/results.json"):
    if not os.path.exists("results"):
        os.makedirs("results")
    if not data:
        data = {"message": "No hosts found"}
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)

def export_to_pdf(data, filename="reports/report.pdf"):
    if not os.path.exists("reports"):
        os.makedirs("reports")
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Vulnerability Scanner Report", ln=True, align="C")
    pdf.ln(10)
    for ip, protocols in data.items():
        pdf.cell(200, 10, txt=f"Host: {ip}", ln=True)
        if isinstance(protocols, list):
            for proto in protocols:
                pdf.cell(200, 10, txt=f"  Protocol: {proto}", ln=True)
        else:
            pdf.cell(200, 10, txt=str(protocols), ln=True)
        pdf.ln(5)
    pdf.output(filename)

def main():
    subnet = input("Enter subnet (e.g., 192.168.1): ")
    print(f"[+] Scanning subnet: {subnet}.0/24")
    results = scan_network(subnet)

    print("[+] Exporting results...")
    export_to_json(results)
    export_to_pdf(results)
    print("[+] Done. Check 'results/results.json' and 'reports/report.pdf'.")

if __name__ == "__main__":
    main()