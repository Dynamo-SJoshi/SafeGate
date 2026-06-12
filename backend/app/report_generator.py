from __future__ import annotations

import json
import urllib.parse
from typing import Any
from datetime import datetime

# Import WeasyPrint only inside functions to avoid startup dependencies issues if libraries are reloading
def generate_pdf_report(record: dict[str, Any]) -> bytes:
    from weasyprint import HTML

    # Extract info
    filename = record.get("original_filename") or "Unknown"
    size_bytes = record.get("size_bytes") or 0
    sha256 = record.get("sha256") or "N/A"
    verdict = record.get("analysis_state") or "clean"
    created_at = record.get("created_at")
    
    # Format size
    if size_bytes < 1024:
        size_str = f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        size_str = f"{size_bytes / 1024:.2f} KB"
    else:
        size_str = f"{size_bytes / (1024 * 1024):.2f} MB"

    # Format date
    if isinstance(created_at, datetime):
        date_str = created_at.strftime("%Y-%m-%d %H:%M:%S UTC")
    elif created_at:
        date_str = str(created_at)[:19]
    else:
        date_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    static_analysis = record.get("static_analysis") or {}
    clamav = static_analysis.get("clamav") or {}
    yara = static_analysis.get("yara") or {}
    exif = static_analysis.get("exiftool") or {}
    sandbox = static_analysis.get("sandbox") or {}

    # 1. Executive Summary & Verdict Styling
    fingerprint = record.get("fingerprint") or {}
    detected_type = fingerprint.get("detected_type") or "unknown"

    if detected_type == "application/zip-bomb" or "zip-bomb-detected" in fingerprint.get("indicators", []):
        verdict_title = "MALICIOUS / ZIP BOMB DETECTED"
        verdict_class = "badge-danger"
        summary_text = (
            "CRITICAL WARNING: This file is a ZIP Bomb (Decompression Bomb) designed to cause resource exhaustion "
            "and Denial of Service (DoS). SafeGate's in-memory header audit detected an anomalous compression ratio "
            "or excessively large uncompressed file structure. Decompressing this archive poses a severe threat of crash or "
            "instability to the execution host. SafeGate has blocked further analysis and skipped secondary scanning."
        )
    elif verdict == "malicious":
        verdict_title = "MALICIOUS / THREAT DETECTED"
        verdict_class = "badge-danger"
        summary_text = (
            "CRITICAL WARNING: Active threats or malicious behaviors have been detected "
            "associated with this resource. SafeGate's security engines identified signature matches "
            "or dangerous dynamic behaviors (such as evasion tactics or unauthorized network actions) "
            "during runtime sandbox inspection. We strongly advise against executing or accessing this file."
        )
    elif verdict == "suspicious":
        verdict_title = "SUSPICIOUS / USE WITH CAUTION"
        verdict_class = "badge-warning"
        summary_text = (
            "ATTENTION: High-risk characteristics or anomalies were identified in this resource. "
            "Although no definitive malware signature was matched, indicators of concern—such as "
            "extension mismatches, obfuscation tactics, or unusual behavior in the sandboxed container—were "
            "flagged. Please proceed with extreme caution."
        )
    else:
        verdict_title = "CLEAN / NO THREATS DETECTED"
        verdict_class = "badge-clean"
        summary_text = (
            "SafeGate has completed all static signature scans and dynamic sandbox analysis "
            "on this resource. No known virus signatures, suspicious metadata anomalies, or "
            "malicious process activity were detected. The file appears safe for normal use."
        )

    # 2. Compute Risk Scores (0-100) for Radar Chart
    # Signatures: ClamAV / YARA
    sig_score = 0
    if clamav.get("verdict") == "infected":
        sig_score = 100
    elif yara.get("verdict") == "suspicious":
        sig_score = 80
    elif len(yara.get("matches", [])) > 0:
        sig_score = 60

    # Metadata Risks: ExifTool / Mime Type mismatch
    meta_score = 0
    fingerprint = record.get("fingerprint") or {}
    match_status = fingerprint.get("match_status") or "match"
    if match_status == "mismatch":
        meta_score += 50
    
    exif_warnings = []
    if isinstance(exif, dict):
        # Scan exiftool warning dictionary entries
        for k, v in exif.items():
            if "warning" in k.lower() or "error" in k.lower():
                exif_warnings.append(str(v))
    meta_score = min(100, meta_score + len(exif_warnings) * 15)

    # Evasion Risk: Sandbox anti-VM / debugger
    evas_score = 0
    sandbox_verdict = sandbox.get("verdict")
    sandbox_sigs = sandbox.get("signatures", [])
    
    evasion_keywords = ["anti-vm", "evasion", "debugger", "sandbox", "delay", "sleep"]
    evasion_matches = [s for s in sandbox_sigs if any(k in s.lower() for k in evasion_keywords)]
    evas_score = min(100, len(evasion_matches) * 30)
    if sandbox_verdict == "malicious" and evas_score == 0:
        evas_score = 50

    # Network Risks: Sandbox domain lookups / socket connections
    net_score = 0
    net_calls = sandbox.get("network", {})
    dns_queries = net_calls.get("dns", [])
    tcp_conns = net_calls.get("tcp", [])
    net_score = min(100, len(dns_queries) * 20 + len(tcp_conns) * 20)
    if net_score == 0 and any("network" in s.lower() or "http" in s.lower() for s in sandbox_sigs):
        net_score = 30

    # Behavior Risks: Process spawning / registry / file writes
    beh_score = 0
    proc_tree = sandbox.get("processes", [])
    file_ops = sandbox.get("files", {})
    file_writes = file_ops.get("written", [])
    beh_score = min(100, len(proc_tree) * 25 + len(file_writes) * 10)
    if sandbox_verdict == "malicious" and beh_score == 0:
        beh_score = 60

    # Overall Score (0-100)
    overall_score = 0
    if verdict == "malicious":
        overall_score = max(75, int((sig_score + evas_score + net_score + beh_score) / 4))
        overall_score = min(100, overall_score)
    elif verdict == "suspicious":
        overall_score = max(35, int((sig_score + meta_score + evas_score + net_score + beh_score) / 5))
        overall_score = min(74, overall_score)
    else:
        overall_score = max(0, int((meta_score + net_score) / 5))
        overall_score = min(34, overall_score)

    # Choose Colors based on verdict
    if verdict == "malicious":
        color_primary = "rgba(239, 68, 68, 1)" # Red
        color_fill = "rgba(239, 68, 68, 0.2)"
        color_hex = "#EF4444"
    elif verdict == "suspicious":
        color_primary = "rgba(245, 158, 11, 1)" # Orange
        color_fill = "rgba(245, 158, 11, 0.2)"
        color_hex = "#F59E0B"
    else:
        color_primary = "rgba(16, 185, 129, 1)" # Green
        color_fill = "rgba(16, 185, 129, 0.2)"
        color_hex = "#10B981"

    # 3. Create QuickChart Radar Chart URL
    radar_config = {
        "type": "radar",
        "data": {
            "labels": ["Signature Match", "Metadata Anomalies", "Evasion Risk", "Network Activity", "Behavior Risk"],
            "datasets": [{
                "label": "Risk Value",
                "data": [sig_score, meta_score, evas_score, net_score, beh_score],
                "backgroundColor": color_fill,
                "borderColor": color_primary,
                "borderWidth": 2,
                "pointBackgroundColor": color_primary,
                "pointRadius": 3
            }]
        },
        "options": {
            "scale": {
                "ticks": {
                    "beginAtZero": True,
                    "max": 100,
                    "stepSize": 25,
                    "fontSize": 9
                },
                "pointLabels": {
                    "fontSize": 10,
                    "fontStyle": "bold"
                }
            },
            "legend": { "display": False }
        }
    }
    radar_url = f"https://quickchart.io/chart?c={urllib.parse.quote(json.dumps(radar_config))}"

    # Build Scanner checklist markup
    scanners = [
        ("ClamAV Antivirus Scanner", 
         "Threat detected" if clamav.get("verdict") == "infected" else "No threats detected",
         "fail" if clamav.get("verdict") == "infected" else "pass"),
        
        ("YARA Signature Rules Engine", 
         f"{len(yara.get('matches', []))} rules matched" if yara.get("verdict") == "suspicious" else "No rules matched",
         "fail" if yara.get("verdict") == "suspicious" else "pass"),
         
        ("ExifTool Metadata Parser", 
         f"{len(exif_warnings)} anomalies flagged" if exif_warnings else "Mime-type matching (PASS)",
         "warning" if exif_warnings or match_status == "mismatch" else "pass"),
         
        ("Dynamic Sandbox Analyzer", 
         "Malicious activity detected" if sandbox_verdict == "malicious" else ("Suspicious activity detected" if sandbox_verdict == "suspicious" else "Behavior clean / No actions"),
         "fail" if sandbox_verdict == "malicious" else ("warning" if sandbox_verdict == "suspicious" else "pass"))
    ]

    checklist_html = ""
    for name, desc, status in scanners:
        if status == "pass":
            badge_html = '<span class="status-pass">&#10004; PASS</span>'
        elif status == "warning":
            badge_html = '<span class="status-warn">&#9888; WARN</span>'
        else:
            badge_html = '<span class="status-fail">&#10008; THREAT</span>'
            
        checklist_html += f"""
        <div class="scanner-row">
            <div class="scanner-name">{name}</div>
            <div class="scanner-desc">{desc}</div>
            <div class="scanner-badge">{badge_html}</div>
        </div>
        """

    # Build behavior list markup
    behavior_html = ""
    if sandbox_sigs:
        behavior_html = "<ul>"
        for sig in sandbox_sigs[:5]: # Max 5 signatures
            behavior_html += f"<li>{sig}</li>"
        behavior_html += "</ul>"
    else:
        behavior_html = "<p class='no-behavior'>No suspicious runtime behaviors observed inside the sandbox container.</p>"

    # HTML Template
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <style>
            @page {{
                size: A4;
                margin: 12mm 15mm;
            }}
            body {{
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                color: #2d3748;
                line-height: 1.4;
                font-size: 13px;
                margin: 0;
                padding: 0;
            }}
            .header {{
                border-bottom: 2px solid #e2e8f0;
                padding-bottom: 10px;
                margin-bottom: 15px;
            }}
            .header-table {{
                width: 100%;
                border-collapse: collapse;
            }}
            .header-title {{
                font-size: 22px;
                font-weight: 800;
                color: #0f172a;
                margin: 0;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }}
            .header-subtitle {{
                font-size: 11px;
                color: #64748b;
                margin: 3px 0 0 0;
            }}
            .badge-container {{
                text-align: right;
                vertical-align: middle;
            }}
            .badge {{
                display: inline-block;
                padding: 6px 14px;
                border-radius: 6px;
                font-weight: 700;
                font-size: 12px;
                text-transform: uppercase;
            }}
            .badge-clean {{
                background-color: #d1fae5;
                color: #065f46;
                border: 1px solid #a7f3d0;
            }}
            .badge-warning {{
                background-color: #fef3c7;
                color: #92400e;
                border: 1px solid #fde68a;
            }}
            .badge-danger {{
                background-color: #fee2e2;
                color: #991b1b;
                border: 1px solid #fecaca;
            }}
            
            .section-summary {{
                background-color: #f8fafc;
                border-left: 4px solid {color_hex};
                padding: 10px 15px;
                margin-bottom: 15px;
                border-radius: 0 6px 6px 0;
            }}
            .section-title {{
                font-size: 13px;
                font-weight: 700;
                color: #475569;
                margin-top: 0;
                margin-bottom: 5px;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }}
            .summary-body {{
                font-size: 13px;
                margin: 0;
                color: #334155;
            }}

            .two-col {{
                width: 100%;
                margin-bottom: 15px;
            }}
            .col-left {{
                width: 53%;
                padding-right: 15px;
                vertical-align: top;
            }}
            .col-right {{
                width: 47%;
                text-align: center;
                vertical-align: top;
            }}

            .card {{
                border: 1px solid #e2e8f0;
                border-radius: 8px;
                padding: 12px;
                margin-bottom: 12px;
                background: #ffffff;
            }}
            .card-title {{
                font-size: 12px;
                font-weight: 700;
                color: #334155;
                margin-top: 0;
                margin-bottom: 10px;
                border-bottom: 1px solid #f1f5f9;
                padding-bottom: 5px;
                text-transform: uppercase;
            }}

            .info-table {{
                width: 100%;
                border-collapse: collapse;
            }}
            .info-table th {{
                text-align: left;
                font-size: 11px;
                color: #64748b;
                padding: 4px 0;
                width: 30%;
                font-weight: 500;
            }}
            .info-table td {{
                font-size: 11px;
                color: #1e293b;
                padding: 4px 0;
                word-break: break-all;
                font-weight: 600;
            }}

            .scanner-row {{
                border-bottom: 1px solid #f1f5f9;
                padding: 6px 0;
                display: table;
                width: 100%;
            }}
            .scanner-row:last-child {{
                border-bottom: none;
                padding-bottom: 0;
            }}
            .scanner-name {{
                display: table-cell;
                width: 45%;
                font-weight: 700;
                font-size: 11px;
                color: #1e293b;
            }}
            .scanner-desc {{
                display: table-cell;
                width: 40%;
                font-size: 10px;
                color: #64748b;
            }}
            .scanner-badge {{
                display: table-cell;
                width: 15%;
                text-align: right;
                vertical-align: middle;
            }}
            .status-pass {{
                font-size: 9px;
                font-weight: 700;
                color: #047857;
                background-color: #d1fae5;
                padding: 2px 6px;
                border-radius: 4px;
            }}
            .status-warn {{
                font-size: 9px;
                font-weight: 700;
                color: #b45309;
                background-color: #fef3c7;
                padding: 2px 6px;
                border-radius: 4px;
            }}
            .status-fail {{
                font-size: 9px;
                font-weight: 700;
                color: #b91c1c;
                background-color: #fee2e2;
                padding: 2px 6px;
                border-radius: 4px;
            }}

            .chart-container {{
                border: 1px solid #e2e8f0;
                border-radius: 8px;
                padding: 8px;
                background: #ffffff;
                display: inline-block;
                width: 90%;
            }}
            .chart-img {{
                max-width: 100%;
                height: auto;
            }}

            .score-card {{
                margin-top: 10px;
                padding: 10px;
                border-radius: 6px;
                background-color: #f8fafc;
                border: 1px dashed #cbd5e1;
            }}
            .score-label {{
                font-size: 11px;
                color: #64748b;
                font-weight: 600;
            }}
            .score-value {{
                font-size: 26px;
                font-weight: 800;
                color: {color_hex};
                margin: 2px 0;
            }}
            .score-bar-bg {{
                height: 6px;
                background-color: #e2e8f0;
                border-radius: 3px;
                overflow: hidden;
                width: 80%;
                margin: 0 auto;
            }}
            .score-bar-fill {{
                height: 100%;
                background-color: {color_hex};
                width: {overall_score}%;
            }}

            .behavior-card ul {{
                margin: 0;
                padding-left: 18px;
                font-size: 11px;
                color: #334155;
            }}
            .behavior-card li {{
                margin-bottom: 4px;
            }}
            .no-behavior {{
                font-size: 11px;
                color: #64748b;
                margin: 0;
                font-style: italic;
            }}
            .footer {{
                position: absolute;
                bottom: 0;
                left: 0;
                right: 0;
                border-top: 1px solid #e2e8f0;
                padding-top: 8px;
                text-align: center;
                font-size: 10px;
                color: #94a3b8;
            }}
        </style>
    </head>
    <body>
        <div class="header">
            <table class="header-table">
                <tr>
                    <td>
                        <h1 class="header-title">SafeGate Security Report</h1>
                        <p class="header-subtitle">Deterministic Analysis Profile &mdash; Generated on {date_str}</p>
                    </td>
                    <td class="badge-container">
                        <span class="badge {verdict_class}">{verdict_title}</span>
                    </td>
                </tr>
            </table>
        </div>

        <div class="section-summary">
            <h2 class="section-title">Executive Summary (Layman Friendly)</h2>
            <p class="summary-body">{summary_text}</p>
        </div>

        <table class="two-col">
            <tr>
                <td class="col-left">
                    <div class="card">
                        <h3 class="card-title">File Information</h3>
                        <table class="info-table">
                            <tr>
                                <th>Name</th>
                                <td>{filename}</td>
                            </tr>
                            <tr>
                                <th>Size</th>
                                <td>{size_str}</td>
                            </tr>
                            <tr>
                                <th>SHA-256</th>
                                <td>{sha256}</td>
                            </tr>
                            <tr>
                                <th>Type</th>
                                <td>{record.get("detected_content_type") or record.get("content_type") or "Unknown"}</td>
                            </tr>
                        </table>
                    </div>

                    <div class="card">
                        <h3 class="card-title">Multi-Layer Scan Checklist</h3>
                        {checklist_html}
                    </div>
                </td>
                <td class="col-right">
                    <div class="chart-container">
                        <h3 class="card-title" style="margin-bottom: 5px;">Risk Profile Vector</h3>
                        <img src="{radar_url}" class="chart-img" alt="Risk Profile Chart">
                    </div>

                    <div class="score-card">
                        <span class="score-label">OVERALL THREAT INDEX</span>
                        <div class="score-value">{overall_score}/100</div>
                        <div class="score-bar-bg">
                            <div class="score-bar-fill"></div>
                        </div>
                    </div>
                </td>
            </tr>
        </table>

        <div class="card behavior-card" style="margin-top: 0;">
            <h3 class="card-title">Top Observed Sandbox Behaviors</h3>
            {behavior_html}
        </div>

        <div class="footer">
            SafeGate Threat Detection Sandbox System &bull; Secured Container Sandbox Analysis Report &bull; Confident Security Verdict
        </div>
    </body>
    </html>
    """
    
    # Render PDF using WeasyPrint
    return HTML(string=html_content).write_pdf()


def get_report_data(record: dict[str, Any]) -> dict[str, Any]:
    # Extract data for frontend interactive dashboard rendering
    filename = record.get("original_filename") or "Unknown"
    size_bytes = record.get("size_bytes") or 0
    sha256 = record.get("sha256") or "N/A"
    verdict = record.get("analysis_state") or "clean"
    
    static_analysis = record.get("static_analysis") or {}
    clamav = static_analysis.get("clamav") or {}
    yara = static_analysis.get("yara") or {}
    exif = static_analysis.get("exiftool") or {}
    sandbox = static_analysis.get("sandbox") or {}

    exif_warnings = []
    if isinstance(exif, dict):
        for k, v in exif.items():
            if "warning" in k.lower() or "error" in k.lower():
                exif_warnings.append(str(v))

    # Re-calculate identical scores for the frontend chart consistency
    sig_score = 0
    if clamav.get("verdict") == "infected":
        sig_score = 100
    elif yara.get("verdict") == "suspicious":
        sig_score = 80
    elif len(yara.get("matches", [])) > 0:
        sig_score = 60

    fingerprint = record.get("fingerprint") or {}
    match_status = fingerprint.get("match_status") or "match"
    meta_score = 50 if match_status == "mismatch" else 0
    meta_score = min(100, meta_score + len(exif_warnings) * 15)

    sandbox_verdict = sandbox.get("verdict")
    sandbox_sigs = sandbox.get("signatures", [])
    evasion_keywords = ["anti-vm", "evasion", "debugger", "sandbox", "delay", "sleep"]
    evasion_matches = [s for s in sandbox_sigs if any(k in s.lower() for k in evasion_keywords)]
    evas_score = min(100, len(evasion_matches) * 30)
    if sandbox_verdict == "malicious" and evas_score == 0:
        evas_score = 50

    net_calls = sandbox.get("network", {})
    dns_queries = net_calls.get("dns", [])
    tcp_conns = net_calls.get("tcp", [])
    net_score = min(100, len(dns_queries) * 20 + len(tcp_conns) * 20)
    if net_score == 0 and any("network" in s.lower() or "http" in s.lower() for s in sandbox_sigs):
        net_score = 30

    proc_tree = sandbox.get("processes", [])
    file_ops = sandbox.get("files", {})
    file_writes = file_ops.get("written", [])
    beh_score = min(100, len(proc_tree) * 25 + len(file_writes) * 10)
    if sandbox_verdict == "malicious" and beh_score == 0:
        beh_score = 60

    overall_score = 0
    detected_type = fingerprint.get("detected_type") or "unknown"
    is_zip_bomb = detected_type == "application/zip-bomb" or "zip-bomb-detected" in fingerprint.get("indicators", [])

    if is_zip_bomb:
        overall_score = 100
        sig_score = 100
        meta_score = 100
        evas_score = 100
        net_score = 0
        beh_score = 0
        summary_text = (
            "CRITICAL WARNING: This file is flagged as a ZIP Bomb (Decompression Bomb). "
            "SafeGate's in-memory header inspection detected an extremely high compression ratio or single-file size anomaly. "
            "Decompressing this archive poses a severe threat of Denial of Service (DoS) and system instability. "
            "Execution and secondary scanning have been bypassed for safety."
        )
    else:
        if verdict == "malicious":
            overall_score = max(75, int((sig_score + evas_score + net_score + beh_score) / 4))
            overall_score = min(100, overall_score)
        elif verdict == "suspicious":
            overall_score = max(35, int((sig_score + meta_score + evas_score + net_score + beh_score) / 5))
            overall_score = min(74, overall_score)
        else:
            overall_score = max(0, int((meta_score + net_score) / 5))
            overall_score = min(34, overall_score)

        if verdict == "malicious":
            summary_text = (
                "WARNING: Critical security risks were detected. Active threat signatures (from antivirus "
                "or security rules) were matched, or highly suspicious sandbox activities (such as network calls "
                "or process spawning) were noted during execution. Do not trust or run this file."
            )
        elif verdict == "suspicious":
            summary_text = (
                "CAUTION: Potential risk indicators were found. Though no outright virus matched, "
                "anomalies in the metadata, file headers, or sandbox behavior patterns suggest a suspicious "
                "profile. Use with severe caution."
            )
        else:
            summary_text = (
                "CLEAN: This file is verified safe. Comprehensive security scans and run-time sandbox "
                "behavior checks were executed. No indicators of malware, malicious actions, or evasion tactics "
                "were detected."
            )

    return {
        "filename": filename,
        "size_bytes": size_bytes,
        "sha256": sha256,
        "verdict": verdict,
        "overall_score": overall_score,
        "summary_text": summary_text,
        "scores": {
            "signature": sig_score,
            "metadata": meta_score,
            "evasion": evas_score,
            "network": net_score,
            "behavior": beh_score
        },
        "scanners": {
            "clamav": clamav,
            "yara": yara,
            "exiftool": exif,
            "exif_warnings_count": len(exif_warnings),
            "sandbox": sandbox
        }
    }
