"use client";

import { useEffect, useState } from "react";

export default function SecurityReport({ uploadId, onClose }) {
  const [reportData, setReportData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState("dashboard"); // "dashboard" or "pdf"

  useEffect(() => {
    async function fetchReport() {
      try {
        setLoading(true);
        setError(null);
        const res = await fetch(`/api/report/${uploadId}`);
        if (!res.ok) {
          const errData = await res.json();
          throw new Error(errData.detail || errData.error || "Failed to fetch report data");
        }
        const data = await res.json();
        setReportData(data);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    }
    fetchReport();
  }, [uploadId]);

  if (!uploadId) return null;

  // Render loading state
  if (loading) {
    return (
      <div className="reportModalOverlay">
        <div className="reportModalContainer" style={{ display: "flex", justifyContent: "center", alignItems: "center", minHeight: "400px" }}>
          <div style={{ textAlign: "center" }}>
            <div className="loader" style={{ margin: "0 auto 16px" }}></div>
            <p style={{ color: "var(--muted)", fontWeight: "500" }}>Compiling report data...</p>
          </div>
        </div>
      </div>
    );
  }

  // Render error state
  if (error) {
    return (
      <div className="reportModalOverlay">
        <div className="reportModalContainer" style={{ padding: "32px", textAlign: "center" }}>
          <h2 style={{ color: "var(--danger)", marginBottom: "16px" }}>Report Generation Failed</h2>
          <p style={{ color: "var(--text)", marginBottom: "24px" }}>{error}</p>
          <button className="ui-btn closeButton" onClick={onClose}>
            <span>Close Window</span>
          </button>
        </div>
      </div>
    );
  }

  const { filename, size_bytes, sha256, verdict, overall_score, summary_text, scores, scanners } = reportData;

  // Format file size
  let sizeStr = `${size_bytes} B`;
  if (size_bytes >= 1024 * 1024) {
    sizeStr = `${(size_bytes / (1024 * 1024)).toFixed(2)} MB`;
  } else if (size_bytes >= 1024) {
    sizeStr = `${(size_bytes / 1024).toFixed(2)} KB`;
  }

  // Determine threat class and label
  let verdictLabel = "Safe / Clean";
  let verdictColorClass = "clean";
  let verdictBgColor = "rgba(16, 185, 129, 0.1)";
  let verdictBorderColor = "rgba(16, 185, 129, 0.3)";
  let verdictTextHex = "#10b981";

  if (verdict === "malicious") {
    verdictLabel = "Threat Detected";
    verdictColorClass = "danger";
    verdictBgColor = "rgba(239, 68, 68, 0.1)";
    verdictBorderColor = "rgba(239, 68, 68, 0.3)";
    verdictTextHex = "#ef4444";
  } else if (verdict === "suspicious") {
    verdictLabel = "Suspicious Profile";
    verdictColorClass = "warn";
    verdictBgColor = "rgba(245, 158, 11, 0.1)";
    verdictBorderColor = "rgba(245, 158, 11, 0.3)";
    verdictTextHex = "#f59e0b";
  }

  // Create QuickChart URL for the Radar Chart
  const radarConfig = {
    type: "radar",
    data: {
      labels: ["Signatures", "Metadata Risks", "Evasion Risk", "Network Risks", "Behavior Risks"],
      datasets: [
        {
          label: "Risk Profile Score",
          data: [
            scores.signature,
            scores.metadata,
            scores.evasion,
            scores.network,
            scores.behavior,
          ],
          backgroundColor: verdict === "malicious" 
            ? "rgba(239, 68, 68, 0.15)" 
            : verdict === "suspicious" 
              ? "rgba(245, 158, 11, 0.15)" 
              : "rgba(0, 113, 226, 0.15)",
          borderColor: verdict === "malicious" 
            ? "#ef4444" 
            : verdict === "suspicious" 
              ? "#f59e0b" 
              : "#0071e2",
          borderWidth: 2,
          pointBackgroundColor: verdict === "malicious" 
            ? "#ef4444" 
            : verdict === "suspicious" 
              ? "#f59e0b" 
              : "#0071e2",
          pointRadius: 3,
        },
      ],
    },
    options: {
      scale: {
        ticks: {
          beginAtZero: true,
          max: 100,
          stepSize: 25,
          fontColor: "#94a3b8",
          fontSize: 9,
          backdropColor: "transparent"
        },
        pointLabels: {
          fontColor: "#cbd5e1",
          fontSize: 10,
          fontStyle: "bold"
        },
        gridLines: {
          color: "rgba(255, 255, 255, 0.08)"
        },
        angleLines: {
          color: "rgba(255, 255, 255, 0.08)"
        }
      },
      legend: { display: false }
    }
  };
  const radarUrl = `https://quickchart.io/chart?c=${encodeURIComponent(JSON.stringify(radarConfig))}`;

  return (
    <div className="reportModalOverlay">
      <div className="reportModalContainer">
        
        {/* Modal Header */}
        <div className="reportModalHeader">
          <div style={{ display: "flex", alignItems: "center", gap: "16px" }}>
            <h1 className="reportModalTitle">SafeGate Analysis Report</h1>
            <span 
              className={`verdictBadge verdictBadge-${verdictColorClass}`}
              style={{
                background: verdictBgColor,
                border: `1px solid ${verdictBorderColor}`,
                color: verdictTextHex,
                padding: "4px 12px",
                borderRadius: "30px",
                fontSize: "0.8rem",
                fontWeight: "700",
                textTransform: "uppercase"
              }}
            >
              {verdictLabel}
            </span>
          </div>
          <button className="reportModalCloseBtn" onClick={onClose} aria-label="Close report">&times;</button>
        </div>

        {/* Modal Controls Toolbar */}
        <div className="reportModalToolbar">
          <div className="reportSegmentedControl">
            <button 
              className={`reportTabButton ${activeTab === "dashboard" ? "active" : ""}`}
              onClick={() => setActiveTab("dashboard")}
            >
              Interactive Dashboard
            </button>
            <button 
              className={`reportTabButton ${activeTab === "pdf" ? "active" : ""}`}
              onClick={() => setActiveTab("pdf")}
            >
              PDF Document Preview
            </button>
          </div>

          <a 
            href={`/api/report/${uploadId}/pdf`}
            download={`SafeGate_Report_${uploadId}.pdf`}
            className="ui-btn downloadReportBtn"
            style={{ textDecoration: "none" }}
          >
            <span>Download PDF Report</span>
          </a>
        </div>

        {/* Modal Content Window */}
        <div className="reportModalContent">
          {activeTab === "dashboard" ? (
            <div className="reportDashboardLayout">
              
              {/* Left Column: Summary and Scanners */}
              <div className="reportDashboardCol">
                
                {/* Layman Summary Card */}
                <div className="reportDashboardCard" style={{ borderLeft: `4px solid ${verdictTextHex}` }}>
                  <h3 className="cardTitle">Executive Summary</h3>
                  <p className="summaryText">{summary_text}</p>
                </div>

                {/* File Information Card */}
                <div className="reportDashboardCard">
                  <h3 className="cardTitle">General File Information</h3>
                  <div className="metaGrid">
                    <div className="metaItem">
                      <span className="metaLabel">Filename:</span>
                      <span className="metaVal" style={{ wordBreak: "break-all" }}>{filename}</span>
                    </div>
                    <div className="metaItem">
                      <span className="metaLabel">File Size:</span>
                      <span className="metaVal">{sizeStr}</span>
                    </div>
                    <div className="metaItem">
                      <span className="metaLabel">SHA-256 Hash:</span>
                      <span className="metaVal" style={{ wordBreak: "break-all", fontFamily: "monospace" }}>{sha256}</span>
                    </div>
                    <div className="metaItem">
                      <span className="metaLabel">Detected MIME:</span>
                      <span className="metaVal">{scanners.exiftool?.MIMEType || scanners.exiftool?.FileType || "Unknown"}</span>
                    </div>
                  </div>
                </div>

                {/* Scanner Checklist Card */}
                <div className="reportDashboardCard">
                  <h3 className="cardTitle">Multi-Layer Scanner Checklist</h3>
                  <div className="scannersChecklist">
                    
                    {/* ClamAV */}
                    {(() => {
                      let clamavDetail = "No malicious signatures matched";
                      let clamavStatus = "Passed";
                      let clamavClass = "pass";

                      if (scanners.clamav?.verdict === "skipped") {
                        clamavDetail = scanners.clamav.details || "Scan skipped for safety: ZIP bomb detected.";
                        clamavStatus = "Skipped";
                        clamavClass = "skip";
                      } else if (scanners.clamav?.verdict === "infected") {
                        clamavDetail = `Infected: ${scanners.clamav.details?.replace("Infected with: ", "") || ""}`;
                        clamavStatus = "Threat Detected";
                        clamavClass = "fail";
                      } else if (scanners.clamav?.verdict === "unavailable") {
                        clamavDetail = "ClamAV service is temporarily unavailable";
                        clamavStatus = "Unavailable";
                        clamavClass = "warn";
                      }

                      return (
                        <div className="scannerRow">
                          <div className="scannerMeta">
                            <span className="scannerTitle">
                              ClamAV Antivirus
                              <span className="info-trigger" tabIndex={0}>
                                <span className="info-icon-badge">i</span>
                                <span className="tooltip-popup">
                                  Antivirus scanner matching the file against signatures of millions of known malware.
                                </span>
                              </span>
                            </span>
                            <span className="scannerDetail">{clamavDetail}</span>
                          </div>
                          <span className={`scannerStatusBadge status-${clamavClass}`}>
                            {clamavStatus}
                          </span>
                        </div>
                      );
                    })()}

                    {/* YARA */}
                    {(() => {
                      let yaraDetail = "No security rules triggered";
                      let yaraStatus = "Passed";
                      let yaraClass = "pass";

                      if (scanners.yara?.verdict === "skipped") {
                        yaraDetail = scanners.yara.details || "Scan skipped for safety: ZIP bomb detected.";
                        yaraStatus = "Skipped";
                        yaraClass = "skip";
                      } else if (scanners.yara?.verdict === "suspicious") {
                        yaraDetail = scanners.yara?.matches?.length 
                          ? `Matched rules: ${scanners.yara.matches.join(", ")}`
                          : "Security rules triggered";
                        yaraStatus = "Warning";
                        yaraClass = "fail";
                      } else if (scanners.yara?.verdict === "error") {
                        yaraDetail = `Scan failed: ${scanners.yara.details || "Unknown error"}`;
                        yaraStatus = "Error";
                        yaraClass = "warn";
                      }

                      return (
                        <div className="scannerRow">
                          <div className="scannerMeta">
                            <span className="scannerTitle">
                              YARA Rules Analyzer
                              <span className="info-trigger" tabIndex={0}>
                                <span className="info-icon-badge">i</span>
                                <span className="tooltip-popup">
                                  Pattern-matching tool that checks for specific exploit scripts, webshells, or suspicious code patterns.
                                </span>
                              </span>
                            </span>
                            <span className="scannerDetail">{yaraDetail}</span>
                          </div>
                          <span className={`scannerStatusBadge status-${yaraClass}`}>
                            {yaraStatus}
                          </span>
                        </div>
                      );
                    })()}

                    {/* ExifTool */}
                    {(() => {
                      let exifDetail = "Metadata tags validated";
                      let exifStatus = "Passed";
                      let exifClass = "pass";

                      if (scanners.exiftool?.status === "skipped") {
                        exifDetail = scanners.exiftool.details || "Scan skipped for safety: ZIP bomb detected.";
                        exifStatus = "Skipped";
                        exifClass = "skip";
                      } else if (scanners.exif_warnings_count > 0) {
                        exifDetail = `${scanners.exif_warnings_count} warning anomalies flagged`;
                        exifStatus = "Anomalies";
                        exifClass = "warn";
                      } else if (scanners.exiftool?.status === "error") {
                        exifDetail = `Scan failed: ${scanners.exiftool.details || "Unknown error"}`;
                        exifStatus = "Error";
                        exifClass = "warn";
                      }

                      return (
                        <div className="scannerRow">
                          <div className="scannerMeta">
                            <span className="scannerTitle">
                              ExifTool Metadata Integrity
                              <span className="info-trigger" tabIndex={0}>
                                <span className="info-icon-badge">i</span>
                                <span className="tooltip-popup">
                                  Parser checking file header tags and metadata for hidden script payloads or extension mismatches.
                                </span>
                              </span>
                            </span>
                            <span className="scannerDetail">{exifDetail}</span>
                          </div>
                          <span className={`scannerStatusBadge status-${exifClass}`}>
                            {exifStatus}
                          </span>
                        </div>
                      );
                    })()}

                    {/* Sandbox */}
                    {(() => {
                      let sandboxDetail = "Clean behavior profile";
                      let sandboxStatus = "Passed";
                      let sandboxClass = "pass";

                      if (scanners.sandbox?.verdict === "skipped") {
                        sandboxDetail = scanners.sandbox?.reason || "Scan skipped or not applicable";
                        sandboxStatus = "Skipped";
                        sandboxClass = "skip";
                      } else if (scanners.sandbox?.verdict === "malicious") {
                        sandboxDetail = "Hostile actions detected during runtime";
                        sandboxStatus = "Threat";
                        sandboxClass = "fail";
                      } else if (scanners.sandbox?.verdict === "suspicious") {
                        sandboxDetail = "Suspicious behavior observed in memory";
                        sandboxStatus = "Warning";
                        sandboxClass = "warn";
                      } else if (scanners.sandbox?.verdict === "error") {
                        sandboxDetail = `Scan failed: ${scanners.sandbox.error || "Unknown error"}`;
                        sandboxStatus = "Error";
                        sandboxClass = "warn";
                      }

                      return (
                        <div className="scannerRow">
                          <div className="scannerMeta">
                            <span className="scannerTitle">
                              Dynamic Container Sandbox
                              <span className="info-trigger" tabIndex={0}>
                                <span className="info-icon-badge">i</span>
                                <span className="tooltip-popup">
                                  Isolated runtime container that executes the file, recording outbound network queries, file operations, and spawned processes.
                                </span>
                              </span>
                            </span>
                            <span className="scannerDetail">{sandboxDetail}</span>
                          </div>
                          <span className={`scannerStatusBadge status-${sandboxClass}`}>
                            {sandboxStatus}
                          </span>
                        </div>
                      );
                    })()}

                  </div>
                </div>

              </div>

              {/* Right Column: Visual Infographics */}
              <div className="reportDashboardCol flex-center">
                
                {/* Overall Threat Meter Gauge */}
                <div className="reportDashboardCard flex-column align-center" style={{ width: "100%" }}>
                  <h3 className="cardTitle text-center">Threat Index</h3>
                  <div className="threatGaugeCircle">
                    <span className="threatGaugeScore" style={{ color: verdictTextHex }}>{overall_score}</span>
                    <span className="threatGaugeMax">/100</span>
                  </div>
                  
                  {/* Layman visual slider gauge */}
                  <div className="threatBarContainer">
                    <div className="threatBarBg">
                      <div className="threatBarFill" style={{ width: `${overall_score}%`, backgroundColor: verdictTextHex }}></div>
                    </div>
                    <div className="threatBarLabels">
                      <span style={{ color: "#10b981", fontSize: "0.75rem", fontWeight: "700" }}>Safe</span>
                      <span style={{ color: "#f59e0b", fontSize: "0.75rem", fontWeight: "700" }}>Suspicious</span>
                      <span style={{ color: "#ef4444", fontSize: "0.75rem", fontWeight: "700" }}>Danger</span>
                    </div>
                  </div>
                </div>

                {/* Radar Chart Card */}
                <div className="reportDashboardCard flex-column align-center" style={{ width: "100%" }}>
                  <h3 className="cardTitle text-center">Risk Profile Vector</h3>
                  <div className="radarChartBox">
                    <img src={radarUrl} alt="QuickChart Radar Graphic" className="radarImg" />
                  </div>
                </div>

                {/* Behavior list card */}
                {scanners.sandbox?.signatures?.length > 0 && (
                  <div className="reportDashboardCard" style={{ width: "100%" }}>
                    <h3 className="cardTitle">Sandbox Behaviors</h3>
                    <ul className="behaviorList">
                      {scanners.sandbox.signatures.map((sig, idx) => (
                        <li key={idx}>{sig}</li>
                      ))}
                    </ul>
                  </div>
                )}

              </div>

            </div>
          ) : (
            // PDF Document Preview View
            <div className="reportPdfPreviewLayout">
              <iframe 
                src={`/api/report/${uploadId}/pdf`}
                width="100%" 
                height="100%" 
                className="reportPdfIframe"
                title="A4 PDF Report Preview"
              />
            </div>
          )}
        </div>

      </div>
    </div>
  );
}
