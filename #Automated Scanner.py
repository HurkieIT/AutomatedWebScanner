#Automated Scanner (Nmap, Nikto, GoBuster, Nuclei)
#Gemaakt door: Jens Cornelius Gijsbertus van den Hurk
#Datum 17-12-2025 - 19-12-2025 (v0.1)
#Edit 27-12-2025 - 28-12-2025 (v1.0)

# __________________________________________

#Intro:
#Voor FireBV wordt er een GrayBox/BlackBox pentest uitgevoerd, om de reconnaissance fase wat te vereenvoudigen implementeren we een automatische scanner.
#Deze scanner is gemaakt met Python, de keuze hiervoor is omdat dit een veel gebruikte programmeertaal is binnen Cyber Security.

#Tot slot is de keuze gemaakt voor Nmap voor Network Discovery, Nikto voor Web server, GoBuster om Bruteforce te verkennen wat de paths zijn binnen de Host en tot slot Nuclei om inzichtelijk vulnerabilities te scannen en dit inzichtelijk te krijgen.
#De verzamelde informatie wordt gestructureerd aangeboden als input voor verdere analyse en rapportage.

# __________________________________________

import subprocess
import json
import xml.etree.ElementTree as ET

def NmapReconnaissanceResults(discovery_xml, os_xml, services_xml):
    return {
        "discovery": discovery_xml,
        "os": os_xml,
        "services": services_xml
    }

def NmapScanFase():

    # Vul je Target IP Network in
    TargetIP = input('Voer het Target IP OF Network in (bijv. 192.168.XXX.XXX | 192.168.XXX.0/24): ')

    output_discovery = "TARGET_discovery.xml"
    output_os_dir = "os_scans"        # optioneel: per-host OS-scan
    output_services_dir = "service_scans"

    # Stap 1: Nmap Network Exploration

    subprocess.run(
        ["nmap", "-sn", TargetIP, "-oX", output_discovery],
        check=True
    )

    print("Nmap Network Discovery Scan voltooid.")
    print("Resultaten opgeslagen in", output_discovery)

    tree = ET.parse(output_discovery)
    root = tree.getroot()

    TargetsUp = []

    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") == "up":
            addr_el = host.find("address")
            if addr_el is not None:
                ip_address = addr_el.get("addr")
                print(f"Gevonden IP: {ip_address}")
                TargetsUp.append(ip_address)

    print(f"Totaal up hosts: {len(TargetsUp)}")

    # input("Druk op Enter om door te gaan naar de OS-scan van alleen deze hosts...")

    # Stap 2: Nmap OS Exploration (alleen HostUps)

    #Alles in één keer (één Nmap-call met alle IP's)
    if TargetsUp:
        subprocess.run(
            ["nmap", "-O"] + TargetsUp + ["-oX", "TARGET_os.xml"],
            check=True
        )
        print("Nmap OS Exploration voltooid voor up hosts.")
        print("Resultaten opgeslagen in TARGET_os.xml")
    else:
        print("Geen up hosts gevonden, OS-scan wordt overgeslagen.")

    # input("Druk op Enter om door te gaan naar de volgende stap...")

    # Stap 3: Nmap Service Discovery (ook alleen HostUps)

    if TargetsUp:
        subprocess.run(
            ["nmap", "-sV"] + TargetsUp + ["-oX", "TARGET_services.xml"],
            check=True
        )
        print("Nmap Service Scan voltooid voor up hosts.")
        print("Resultaten opgeslagen in TARGET_services.xml")
    else:
        print("Geen up hosts gevonden, services-scan wordt overgeslagen.")

    # input("Druk op Enter om door te gaan naar de volgende stap...")

# Target_discovery.xml + Targetos.xml + Target_services.xml
# Combineren van de verschillende XML-bestanden in één overzichtelijk bestand.

    CompleteScan = NmapReconnaissanceResults(
    "TARGET_discovery.xml",
    "TARGET_os.xml",
    "TARGET_services.xml"
    )

    return CompleteScan

######


def IsPortOpen(port):
    state = port.find("state")
    return state is not None and state.get("state") == "open"

def DetectWebService(service_name, portid):
    """
    Normaliseert Nmap service naming.
    Geeft terug: (is_web, protocol) waarbij protocol 'http' of 'https' is.
    """
    s = (service_name or "").lower()
    # web als er "http" in de servicenaam zit (bv http, ssl/http, http-alt)
    is_web = "http" in s
    if not is_web:
        return (False, None)

    # https als ssl/https voorkomt, of als port 443 is
    is_https = ("ssl" in s) or ("https" in s) or (str(portid) == "443")
    return (True, "https" if is_https else "http")


#Stap 4: Web Application Scanning met Nikto, Webserver scanning en TLS/SSL Validatie.
# ALS nmap met -sV een Target vind die een Web Application heeft,
# zoals HTTP/HTTPS, dan start Nikto.

def NiktoWebScan(CompleteScan):
    ScanResults = []

    tree = ET.parse(CompleteScan["services"])
    root = tree.getroot()

    for host in root.findall("host"):
        addr_el = host.find("address")
        if addr_el is None:
            continue

        ip_address = addr_el.get("addr")

        for port in host.findall(".//port"):
            if not IsPortOpen(port):
                continue

            service = port.find("service")
            if service is None:
                continue

            service_name = service.get("name")
            portid = port.get("portid")

            is_web, protocol = DetectWebService(service_name, portid)
            if not is_web:
                continue

            target = f"{protocol}://{ip_address}:{portid}"
            output_file = f"Nikto_{protocol.upper()}_{ip_address}_{portid}.xml"

            print(f"[+] Start Nikto {protocol.upper()} scan op {target}")

            command = ["nikto", "-h", target, "-o", output_file, "-Format", "xml"]
            if protocol == "https":
                command.insert(2, "-ssl")

            subprocess.run(command, check=False)

            ScanResults.append({
                "host": ip_address,
                "protocol": protocol,
                "port": portid,
                "ssl": protocol == "https",
                "output": output_file
            })

    return {
        "tool": "Nikto",
        "total_scans": len(ScanResults),
        "results": ScanResults
    }

    # input("Druk op Enter om door te gaan naar de volgende stap...")

#Stap 7 Web Path scanning met GoBuster.
# Gebruik GoBuster om Paths te herkennen (bijv. /admin)

def GoBusterPathScan(CompleteScan):
    ScanResults = []

    tree = ET.parse(CompleteScan["services"])
    root = tree.getroot()

    for host in root.findall("host"):
        addr_el = host.find("address")
        if addr_el is None:
            continue

        ip_address = addr_el.get("addr")

        for port in host.findall(".//port"):
            if not IsPortOpen(port):
                continue

            service = port.find("service")
            if service is None:
                continue

            service_name = service.get("name")
            portid = port.get("portid")

            is_web, protocol = DetectWebService(service_name, portid)
            if not is_web:
                continue

            target = f"{protocol}://{ip_address}:{portid}"
            output_file = f"GoBuster_{protocol.upper()}_{ip_address}_{portid}.txt"

            print(f"[+] Start GoBuster scan op {target}")

            command = [
                "gobuster", "dir",
                "-u", target,
                "-w", "/usr/share/wordlists/dirb/common.txt",
                "-o", output_file
            ]

            if protocol == "https":
                command.append("-k")

            subprocess.run(command, check=False)

            ScanResults.append({
                "host": ip_address,
                "protocol": protocol,
                "port": portid,
                "output": output_file
            })

    return {
        "tool": "GoBuster",
        "total_scans": len(ScanResults),
        "results": ScanResults
    }

# input("Druk op Enter om door te gaan naar de volgende stap...")
 
#Stap 8 Vulnerability Scanning met Nuclei.
#Alle Informatie die verzameld is: Start Nuclei, structureer, Laat zien welke Findings er zijn, Welke CVEs Welke Severity en Referenties ofcourse.

def NucleiVulnerabilityScan(CompleteScan):
    ScanResults = []

    tree = ET.parse(CompleteScan["services"])
    root = tree.getroot()

    for host in root.findall("host"):
        addr_el = host.find("address")
        if addr_el is None:
            continue

        ip_address = addr_el.get("addr")

        for port in host.findall(".//port"):
            if not IsPortOpen(port):
                continue
        
            service = port.find("service")
            if service is None:
                continue
        
            service_name = service.get("name")
            portid = port.get("portid")
        
            is_web, protocol = DetectWebService(service_name, portid)
            if not is_web:
                continue
        
            target = f"{protocol}://{ip_address}:{portid}"
            output_file = f"Nuclei_{ip_address}_{portid}.json"
        
            print(f"[+] Start Nuclei scan op {target}")
        
            subprocess.run(
                ["nuclei", "-u", target, "-jsonl", "-o", output_file],
                check=False
            )
        
            ScanResults.append({
                "host": ip_address,
                "port": portid,
                "service": service_name,
                "output": output_file
            })

    LetsgoBoys = {
        "tool": "Nuclei",
        "total_scans": len(ScanResults),
        "results": ScanResults
    }

    return LetsgoBoys

# input("Druk op Enter om door te gaan naar de volgende stap...")

# ____________________________________________


# Nuclei JSON Parser voor CVE, Severity, Description, References Extractie

def ParseNucleiJSON(output_file):
    findings = []

    try:
        with open(output_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                data = json.loads(line)

                info = data.get("info", {})
                classification = info.get("classification", {})

                cve_list = classification.get("cve-id", []) or info.get("cve", []) or []
                cve = cve_list[0] if isinstance(cve_list, list) and cve_list else "UNKNOWN"

                severity = info.get("severity", "UNKNOWN")
                description = info.get("name", "Kwetsbaarheid gedetecteerd door Nuclei.")
                references = info.get("reference", [])

                if not isinstance(references, list):
                    references = [str(references)]

                findings.append({
                    "cve": cve,
                    "severity": severity,
                    "description": description,
                    "references": references
                })

    except Exception:
        pass

    return findings

    # input("Druk op Enter om door te gaan naar de volgende stap...")

#Parse GoBuster Output voor Path en Status Code Extractie

def ParseGoBusterOutput(output_file):
    entries = []

    try:
        with open(output_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()

                if not line.startswith("/"):
                    continue

                # Verwachte formats:
                # /admin (Status: 403) [Size: 287]
                # /login (Status: 200)
                path = line.split()[0]

                status = "unknown"
                marker = "Status:"
                if marker in line:
                    after = line.split(marker, 1)[1].strip()   # bv "403) [Size: 287]"
                    status = "".join(ch for ch in after if ch.isdigit()) or "unknown"

                entries.append(f"{path} ({status})")

    except Exception:
        pass

    return entries

# input("Druk op Enter om door te gaan naar de volgende stap...")

#Print Resultaten Scan 
#Intelligentie toegevoegd voor eventuele Purple Teaming Resultaten, CVE's, Severity, Referenties inzichtelijk voor Adviesrapporten of Pentests.

def BuildFinalReconReport(ReconResultsRaw):
    ReconnaissanceReport = {
        "hosts": {}
    }

    # ==== Nmap Service Detectie Fase =====

    tree_services = ET.parse(ReconResultsRaw["Nmap"]["services"])
    root_services = tree_services.getroot()

    for host in root_services.findall("host"):
        ip = host.find("address").get("addr")

        ReconnaissanceReport["hosts"][ip] = {
            "ip": ip,
            "os": None,
            "services": {}
        }

        for port in host.findall(".//port"):
            portid = port.get("portid")
            service_el = port.find("service") 
            service_name = service_el.get("name") if service_el is not None else "unknown"

            ReconnaissanceReport["hosts"][ip]["services"][portid] = {
                "service": service_name,
                "paths": [],
                "weaknesses": [],
                "vulnerabilities": []
            }

    # ===== Nmap OS Detectie Fase =======

    try:
        tree_os = ET.parse(ReconResultsRaw["Nmap"]["os"])
        root_os = tree_os.getroot()

        for host in root_os.findall("host"):
            ip = host.find("address").get("addr")
            osmatch = host.find(".//osmatch")
            if osmatch is not None:
                ReconnaissanceReport["hosts"][ip]["os"] = osmatch.get("name")
    except Exception:
        pass  # OS-detectie is optioneel

    # ===== Nikto Web Server Scanning Fase =======

    for result in ReconResultsRaw["Nikto"]["results"]:
        ip = result["host"]
        protocol = result["protocol"]

        for service in ReconnaissanceReport["hosts"][ip]["services"].values():
            if protocol in service["service"]:
                service["weaknesses"].append({
                    "tool": "Nikto",
                    "ssl": result["ssl"],
                    "output": result["output"]
                })

    # ====== GoBuster Path Scanning Fase =======

    for result in ReconResultsRaw["GoBuster"]["results"]:
        ip = result["host"]
        protocol = result["protocol"]

        for service in ReconnaissanceReport["hosts"][ip]["services"].values():
            if protocol in service["service"]:
                service["paths"].append({
                    "tool": "GoBuster",
                    "output": result["output"],
                    "entries": ParseGoBusterOutput(result["output"])
                })

    # ======= Nuclei Vulnerability Scanning Fase ========

    for result in ReconResultsRaw["Nuclei"]["results"]:
        ip = result["host"]
        port = result["port"]

        nuclei_findings = ParseNucleiJSON(result["output"])

        for finding in nuclei_findings:
            vuln = {
                "tool": "Nuclei",
                "service": result["service"],
                "output": result["output"],

                "cve": finding["cve"],
                "severity": finding["severity"],
                "description": finding["description"],
                "references": finding["references"],

                # Intelligence verrijking
                "finding_type": "Remote Service Vulnerability",
                "attack_phase": "Initial Access",
                "source_confidence": "High (CVE-based detection)" if finding["cve"] != "UNKNOWN" else "Medium",

                "impact": "Afhankelijk van context kan misbruik leiden tot systeemcompromittering.",
                "solution": "Patch of mitigatie toepassen volgens vendor.",
                "usable_for_attack": finding["severity"] in ["high", "critical"]
            }

            if ip in ReconnaissanceReport["hosts"] and port in ReconnaissanceReport["hosts"][ip]["services"]:
                ReconnaissanceReport["hosts"][ip]["services"][port]["vulnerabilities"].append(vuln)

    # ===== Host-level Intelligence Samenvatting =====

    for host_ip, host_data in ReconnaissanceReport["hosts"].items():
        total_services = len(host_data["services"])
        total_vulns = 0
        highest_severity = "none"

        severity_order = ["none", "info", "low", "medium", "high", "critical"]

        for service in host_data["services"].values():
            for vuln in service["vulnerabilities"]:
                total_vulns += 1
                sev = (vuln.get("severity") or "none").lower()
                if sev not in severity_order:
                    sev = "info"
                if severity_order.index(sev) > severity_order.index(highest_severity):     
                    highest_severity = sev

        host_data["summary"] = {
            "total_services": total_services,
            "total_vulnerabilities": total_vulns,
            "highest_severity": highest_severity
        }

        if highest_severity in ["critical", "high"]:
            host_data["risk_level"] = "High"
        elif highest_severity == "medium":
            host_data["risk_level"] = "Medium"
        else:
            host_data["risk_level"] = "Low"

    return ReconnaissanceReport

print("[*] Automated Scanner gestart")

nmap_results = NmapScanFase()
nikto_results = NiktoWebScan(nmap_results)
gobuster_results = GoBusterPathScan(nmap_results)
nuclei_results = NucleiVulnerabilityScan(nmap_results)

final_report = BuildFinalReconReport({
    "Nmap": nmap_results,
    "Nikto": nikto_results,
    "GoBuster": gobuster_results,
    "Nuclei": nuclei_results
})

print("\n Scan afgerond")
print(json.dumps(final_report, indent=4))

# ______________Done for Now.___________________
