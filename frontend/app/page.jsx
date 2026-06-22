"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import GeminiAssistant from "./GeminiAssistant";
import GeminiZipItemAssistant from "./GeminiZipItemAssistant";
import SecurityReport from "./SecurityReport";

const ZIP_EXPLORER_SESSION_PREFIX = "safegate.zipExplorerSession:";

function readZipExplorerSession(uploadId) {
  if (typeof window === "undefined" || !uploadId) return null;
  try {
    const raw = window.sessionStorage.getItem(`${ZIP_EXPLORER_SESSION_PREFIX}${uploadId}`);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

function writeZipExplorerSession(uploadId, state) {
  if (typeof window === "undefined" || !uploadId) return;
  try {
    window.sessionStorage.setItem(`${ZIP_EXPLORER_SESSION_PREFIX}${uploadId}`, JSON.stringify(state));
  } catch {
    // Ignore storage failures and fall back to in-memory state.
  }
}

function renderStaticAnalysis(result) {
  if (!result || result.error || result.detail) return null;
  const state = result.analysis_state || "pending";
  const staticRes = result.static_analysis || {};
  const clamav = staticRes.clamav || {};
  const yara = staticRes.yara || {};
  const exif = staticRes.exiftool || {};
  const sandbox = staticRes.sandbox || null;

  let badgeColor = "var(--warn)";
  let badgeLabel = "Pending";
  if (state === "clean") {
    badgeColor = "var(--good)";
    badgeLabel = "Clean";
  } else if (state === "unverified") {
    badgeColor = "var(--muted)";
    badgeLabel = "Unverified";
  } else if (state === "suspicious") {
    badgeColor = "var(--warn)";
    badgeLabel = "Suspicious";
  } else if (state === "malicious") {
    badgeColor = "var(--bad)";
    badgeLabel = "Malicious";
  }

  const indicators = result.fingerprint?.indicators || [];
  const hasDoubleExt = indicators.includes("double-extension-detected");
  const hasZipSlip = indicators.includes("zip-slip-detected");
  const hasZipBomb = indicators.includes("zip-bomb-detected");

  const exifMetadata = exif.status === "success" && exif.metadata ? exif.metadata : null;
  const exifKeys = exifMetadata ? Object.keys(exifMetadata).slice(0, 15) : [];

  return (
    <div className="fingerprintSummary">
      <h3>Analysis Verdict</h3>

      {hasDoubleExt && (
        <div style={{
          border: "1px solid rgba(245, 158, 11, 0.4)",
          background: "rgba(245, 158, 11, 0.08)",
          padding: "12px",
          borderRadius: "12px",
          marginBottom: "16px",
          display: "flex",
          gap: "10px",
          alignItems: "flex-start"
        }}>
          <span style={{ fontSize: "1.25rem", color: "#f59e0b" }}>⚠️</span>
          <div>
            <strong style={{ color: "#f59e0b", display: "block" }}>Double Extension Alert</strong>
            <span style={{ fontSize: "0.85rem", color: "var(--muted)" }}>
              This file has a double extension (e.g. <code>.pdf.exe</code>), which is a common trick used to mask executable files as safe documents. Use caution before opening this file.
            </span>
          </div>
        </div>
      )}

      {hasZipSlip && (
        <div style={{
          border: "1px solid rgba(239, 68, 68, 0.4)",
          background: "rgba(239, 68, 68, 0.08)",
          padding: "12px",
          borderRadius: "12px",
          marginBottom: "16px",
          display: "flex",
          gap: "10px",
          alignItems: "flex-start"
        }}>
          <span style={{ fontSize: "1.25rem", color: "#ef4444" }}>⚠️</span>
          <div>
            <strong style={{ color: "#ef4444", display: "block" }}>Zip Slip Vulnerability Payload Detected</strong>
            <span style={{ fontSize: "0.85rem", color: "var(--muted)" }}>
              One or more file paths inside this archive contain directory traversal sequences (like <code>../</code>) targeting system folders. Unpacking this archive on vulnerable systems is extremely dangerous.
            </span>
          </div>
        </div>
      )}

      {hasZipBomb && (
        <div style={{
          border: "1px solid rgba(239, 68, 68, 0.4)",
          background: "rgba(239, 68, 68, 0.08)",
          padding: "12px",
          borderRadius: "12px",
          marginBottom: "16px",
          display: "flex",
          gap: "10px",
          alignItems: "flex-start"
        }}>
          <span style={{ fontSize: "1.25rem", color: "#ef4444" }}>⚠️</span>
          <div>
            <strong style={{ color: "#ef4444", display: "block" }}>ZIP Bomb Threat Detected</strong>
            <span style={{ fontSize: "0.85rem", color: "var(--muted)" }}>
              This archive exhibits extreme compression ratios or size indicators consistent with a ZIP Bomb. Decompression is blocked to protect the host system from Denial of Service (DoS) / crash.
            </span>
          </div>
        </div>
      )}

      <div style={{ display: "flex", gap: "12px", alignItems: "center", marginBottom: "16px" }}>
        <span
          className="badge"
          style={{
            backgroundColor: badgeColor,
            color: "#08111f",
            fontWeight: "bold",
            padding: "6px 14px",
            borderRadius: "12px",
            fontSize: "0.95rem"
          }}
        >
          {badgeLabel.toUpperCase()}
        </span>
        <span style={{ color: "var(--muted)", fontSize: "0.9rem" }}>
          SHA256: {result.sha256 ? `${result.sha256.substring(0, 16)}...` : "N/A"}
        </span>
      </div>

      <div className="staticAnalyzersGrid" style={{ display: "grid", gap: "16px", marginTop: "12px" }}>
        {/* ClamAV */}
        <div className="analyzerCard" style={{ border: "1px solid var(--panel-border)", padding: "12px", borderRadius: "12px", background: "rgba(255,255,255,0.02)" }}>
          <h4 style={{ margin: "0 0 8px 0", color: "var(--accent)", display: "flex", alignItems: "center" }}>
            ClamAV Antivirus
            <span className="info-trigger" tabIndex={0}>
              <span className="info-icon-badge">i</span>
              <span className="tooltip-popup">
                Antivirus scanner matching the file against signatures of millions of known malware.
              </span>
            </span>
          </h4>
          <p style={{ margin: 0 }}>
            Verdict: <strong style={{ color: clamav.verdict === "infected" ? "var(--bad)" : "inherit" }}>
              {clamav.verdict ? clamav.verdict.toUpperCase() : "NOT RUN"}
            </strong>
          </p>
          {clamav.details && <p style={{ margin: "4px 0 0 0", fontSize: "0.85rem", color: "var(--muted)" }}>{clamav.details}</p>}
        </div>

        {/* YARA */}
        <div className="analyzerCard" style={{ border: "1px solid var(--panel-border)", padding: "12px", borderRadius: "12px", background: "rgba(255,255,255,0.02)" }}>
          <h4 style={{ margin: "0 0 8px 0", color: "var(--accent)", display: "flex", alignItems: "center" }}>
            YARA Signatures
            <span className="info-trigger" tabIndex={0}>
              <span className="info-icon-badge">i</span>
              <span className="tooltip-popup">
                Pattern-matching tool that checks for specific exploit scripts, webshells, or suspicious code patterns.
              </span>
            </span>
          </h4>
          <p style={{ margin: 0 }}>
            Verdict: <strong>{yara.verdict ? yara.verdict.toUpperCase() : "NOT RUN"}</strong>
          </p>
          {yara.details && <p style={{ margin: "4px 0 0 0", fontSize: "0.85rem", color: "var(--muted)" }}>{yara.details}</p>}
          {yara.matches && yara.matches.length > 0 && (
            <div style={{ marginTop: "8px" }}>
              <p style={{ margin: "0 0 4px 0", fontSize: "0.85rem", fontWeight: "bold" }}>Matches:</p>
              <ul style={{ margin: 0, paddingLeft: "16px", fontSize: "0.85rem" }}>
                {yara.matches.map((m, idx) => (
                  <li key={idx} style={{ color: "var(--bad)" }}>
                    Rule: <code>{m.rule}</code> {m.meta?.description ? `- ${m.meta.description}` : ""}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>

        {/* ExifTool Metadata */}
        {exifMetadata && (
          <div className="analyzerCard" style={{ border: "1px solid var(--panel-border)", padding: "12px", borderRadius: "12px", background: "rgba(255,255,255,0.02)" }}>
            <h4 style={{ margin: "0 0 8px 0", color: "var(--accent)", display: "flex", alignItems: "center" }}>
              ExifTool Metadata
              <span className="info-trigger" tabIndex={0}>
                <span className="info-icon-badge">i</span>
                <span className="tooltip-popup">
                  Parser checking file header tags and metadata for hidden script payloads or extension mismatches.
                </span>
              </span>
            </h4>
            <div style={{ maxHeight: "200px", overflowY: "auto", fontSize: "0.85rem" }}>
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <tbody>
                  {exifKeys.map((key) => (
                    <tr key={key} style={{ borderBottom: "1px solid rgba(255,255,255,0.05)" }}>
                      <td style={{ padding: "4px 8px 4px 0", color: "var(--muted)", fontWeight: "bold" }}>{key}</td>
                      <td style={{ padding: "4px 0", wordBreak: "break-all" }}>{String(exifMetadata[key])}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {Object.keys(exifMetadata).length > 15 && (
                <p style={{ margin: "8px 0 0 0", fontSize: "0.8rem", color: "var(--muted)", fontStyle: "italic" }}>
                  Showing first 15 of {Object.keys(exifMetadata).length} metadata fields.
                </p>
              )}
            </div>
          </div>
        )}

        {/* Dynamic Sandbox */}
        {sandbox && (
          <div className="analyzerCard" style={{ border: "1px solid var(--panel-border)", padding: "12px", borderRadius: "12px", background: "rgba(255,255,255,0.02)" }}>
            <h4 style={{ margin: "0 0 8px 0", color: "var(--accent)", display: "flex", alignItems: "center" }}>
              Dynamic Sandbox
              <span className="info-trigger" tabIndex={0}>
                <span className="info-icon-badge">i</span>
                <span className="tooltip-popup">
                  Isolated runtime container that executes the file, recording outbound network queries, file operations, and spawned processes.
                </span>
              </span>
            </h4>
            <p style={{ margin: 0 }}>
              Verdict: <strong style={{ color: sandbox.verdict === "malicious" ? "var(--bad)" : sandbox.verdict === "suspicious" ? "var(--warn)" : "inherit" }}>
                {sandbox.verdict ? sandbox.verdict.toUpperCase() : "NOT RUN"}
              </strong>
            </p>
            {sandbox.reason && <p style={{ margin: "4px 0 0 0", fontSize: "0.85rem", color: "var(--muted)", fontStyle: "italic" }}>{sandbox.reason}</p>}
            {sandbox.details && <p style={{ margin: "4px 0 0 0", fontSize: "0.85rem", color: "var(--muted)" }}>{sandbox.details}</p>}
            {sandbox.behavior_alerts && sandbox.behavior_alerts.length > 0 && (
              <div style={{ marginTop: "8px" }}>
                <p style={{ margin: "0 0 4px 0", fontSize: "0.85rem", fontWeight: "bold", color: "var(--bad)" }}>Behavior Alerts:</p>
                <ul style={{ margin: 0, paddingLeft: "16px", fontSize: "0.85rem" }}>
                  {sandbox.behavior_alerts.map((alert, idx) => (
                    <li key={idx} style={{ color: "var(--bad)" }}>
                      {alert}
                    </li>
                  ))}
                </ul>
              </div>
            )}
            {sandbox.logs && (
              <div style={{ marginTop: "12px" }}>
                <p style={{ margin: "0 0 4px 0", fontSize: "0.85rem", fontWeight: "bold" }}>Sandbox Execution Logs:</p>
                <pre style={{
                  margin: 0,
                  padding: "8px",
                  background: "rgba(0,0,0,0.3)",
                  borderRadius: "6px",
                  fontSize: "0.75rem",
                  maxHeight: "120px",
                  overflowY: "auto",
                  color: "var(--muted)",
                  whiteSpace: "pre-wrap"
                }}>{sandbox.logs}</pre>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function buildTree(items) {
  const root = { name: "Root", isDirectory: true, children: {} };
  for (const item of items) {
    const pathParts = item.name.split("/").filter((p) => p);
    let current = root;
    for (let i = 0; i < pathParts.length; i++) {
      const part = pathParts[i];
      const isLast = i === pathParts.length - 1;
      const isDir = item.is_directory || !isLast;
      if (!current.children[part]) {
        current.children[part] = {
          name: part,
          fullName: pathParts.slice(0, i + 1).join("/"),
          isDirectory: isDir,
          children: {},
          size: isLast ? item.size : null,
          compressed_size: isLast ? item.compressed_size : null,
          isPotentialZipSlip: isLast ? item.is_potential_zip_slip : false,
        };
      }
      current = current.children[part];
    }
  }

  function sortTreeNodes(node) {
    const children = Object.values(node.children);
    children.sort((a, b) => {
      if (a.isDirectory && !b.isDirectory) return -1;
      if (!a.isDirectory && b.isDirectory) return 1;
      return a.name.localeCompare(b.name);
    });
    node.sortedChildren = children;
    children.forEach(sortTreeNodes);
  }

  sortTreeNodes(root);
  return root;
}

function TreeNode({ node, onSelectFile, selectedFile, expandedDirs, toggleDir }) {
  if (node.name === "Root") {
    return (
      <div className="tree-root">
        {node.sortedChildren.map((child) => (
          <TreeNode
            key={child.fullName}
            node={child}
            onSelectFile={onSelectFile}
            selectedFile={selectedFile}
            expandedDirs={expandedDirs}
            toggleDir={toggleDir}
          />
        ))}
      </div>
    );
  }

  if (node.isDirectory) {
    const isExpanded = expandedDirs[node.fullName] !== false;
    return (
      <div className="tree-folder">
        <div className="tree-folder-header" onClick={() => toggleDir(node.fullName)}>
          <span className="folder-icon">{isExpanded ? "📂" : "📁"}</span>
          <span className="folder-name">{node.name}</span>
        </div>
        {isExpanded && (
          <div className="tree-folder-children">
            {node.sortedChildren.map((child) => (
              <TreeNode
                key={child.fullName}
                node={child}
                onSelectFile={onSelectFile}
                selectedFile={selectedFile}
                expandedDirs={expandedDirs}
                toggleDir={toggleDir}
              />
            ))}
          </div>
        )}
      </div>
    );
  }

  const isSelected = selectedFile?.fullName === node.fullName;
  const ext = "." + node.name.split(".").pop().toLowerCase();
  const previewableExts = new Set([".txt", ".py", ".js", ".json", ".sh", ".ini", ".md", ".csv", ".yaml", ".yml", ".xml", ".html", ".css", ".sql", ".conf", ".cfg", ".ps1"]);
  const isPreviewable = previewableExts.has(ext);
  const isPotentialZipSlip = node.isPotentialZipSlip;

  return (
    <div
      className={`tree-file ${isSelected ? "selected" : ""} ${isPotentialZipSlip ? "zip-slip-threat" : (isPreviewable ? "previewable" : "binary")}`}
      onClick={() => onSelectFile(node, isPreviewable)}
      style={isPotentialZipSlip ? { border: "1px solid rgba(255, 75, 75, 0.4)", background: "rgba(255, 75, 75, 0.1)" } : {}}
    >
      <span className="file-icon">{isPotentialZipSlip ? "⚠️" : (isPreviewable ? "📄" : "⚙️")}</span>
      <span className="file-name" style={isPotentialZipSlip ? { color: "#ff8888", fontWeight: "bold" } : {}}>{node.name}</span>
      {node.size !== null && node.size !== undefined && (
        <span className="file-size">({(node.size / 1024).toFixed(1)} KB)</span>
      )}
      {isPotentialZipSlip && <span className="zip-slip-badge" style={{ background: "#ff4444", color: "#fff", padding: "2px 6px", fontSize: "10px", borderRadius: "3px", marginLeft: "6px", fontWeight: "bold" }}>ZIP SLIP THREAT</span>}
      <button type="button" className="view-btn">{isPotentialZipSlip ? "Inspect Threat" : (isPreviewable ? "View" : "Inspect")}</button>
    </div>
  );
}

function renderZipItemScanResults(scanResults) {
  if (!scanResults) return null;
  const state = scanResults.verdict || "clean";
  const clamav = scanResults.clamav || {};
  const yara = scanResults.yara || {};
  const exif = scanResults.exiftool || {};
  const sandbox = scanResults.sandbox || null;

  let badgeColor = "var(--warn)";
  let badgeLabel = "Pending";
  if (state === "clean") {
    badgeColor = "var(--good)";
    badgeLabel = "Clean";
  } else if (state === "unverified") {
    badgeColor = "var(--muted)";
    badgeLabel = "Unverified";
  } else if (state === "suspicious") {
    badgeColor = "var(--warn)";
    badgeLabel = "Suspicious";
  } else if (state === "malicious") {
    badgeColor = "var(--bad)";
    badgeLabel = "Malicious";
  }

  const exifMetadata = exif.status === "success" && exif.metadata ? exif.metadata : null;
  const exifKeys = exifMetadata ? Object.keys(exifMetadata).slice(0, 15) : [];

  return (
    <div className="fingerprintSummary" style={{ marginTop: "20px", background: "rgba(10, 20, 40, 0.3)", border: "1px solid rgba(140, 170, 255, 0.15)" }}>
      <h3 style={{ borderBottom: "1px solid rgba(140, 170, 255, 0.12)", paddingBottom: "8px", color: "#fff" }}>Security Analysis Verdict</h3>
      <div style={{ display: "flex", gap: "12px", alignItems: "center", marginBottom: "16px", marginTop: "12px" }}>
        <span
          className="badge"
          style={{
            backgroundColor: badgeColor,
            color: "#08111f",
            fontWeight: "bold",
            padding: "4px 12px",
            borderRadius: "10px",
            fontSize: "0.85rem"
          }}
        >
          {badgeLabel.toUpperCase()}
        </span>
      </div>

      <div className="staticAnalyzersGrid" style={{ display: "grid", gridTemplateColumns: "1fr", gap: "16px", marginTop: "12px" }}>
        {/* ClamAV */}
        <div className="analyzerCard" style={{ border: "1px solid rgba(140, 170, 255, 0.1)", padding: "12px", borderRadius: "12px", background: "rgba(255,255,255,0.01)" }}>
          <h4 style={{ margin: "0 0 6px 0", color: "var(--accent)", fontSize: "0.9rem" }}>ClamAV Antivirus</h4>
          <p style={{ margin: 0, fontSize: "0.85rem" }}>
            Verdict: <strong style={{ color: clamav.verdict === "infected" ? "var(--bad)" : "inherit" }}>
              {clamav.verdict ? clamav.verdict.toUpperCase() : "NOT RUN"}
            </strong>
          </p>
          {clamav.details && <p style={{ margin: "4px 0 0 0", fontSize: "0.8rem", color: "var(--muted)" }}>{clamav.details}</p>}
        </div>

        {/* YARA */}
        <div className="analyzerCard" style={{ border: "1px solid rgba(140, 170, 255, 0.1)", padding: "12px", borderRadius: "12px", background: "rgba(255,255,255,0.01)" }}>
          <h4 style={{ margin: "0 0 6px 0", color: "var(--accent)", fontSize: "0.9rem" }}>YARA Rules</h4>
          <p style={{ margin: 0, fontSize: "0.85rem" }}>
            Verdict: <strong>{yara.verdict ? yara.verdict.toUpperCase() : "NOT RUN"}</strong>
          </p>
          {yara.details && <p style={{ margin: "4px 0 0 0", fontSize: "0.8rem", color: "var(--muted)" }}>{yara.details}</p>}
          {yara.matches && yara.matches.length > 0 && (
            <div style={{ marginTop: "8px" }}>
              <p style={{ margin: "0 0 4px 0", fontSize: "0.8rem", fontWeight: "bold" }}>Matches:</p>
              <ul style={{ margin: 0, paddingLeft: "16px", fontSize: "0.8rem" }}>
                {yara.matches.map((m, idx) => (
                  <li key={idx} style={{ color: "var(--bad)" }}>
                    Rule: <code>{m.rule}</code> {m.meta?.description ? `- ${m.meta.description}` : ""}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>

        {/* ExifTool Metadata */}
        {exifMetadata && (
          <div className="analyzerCard" style={{ border: "1px solid rgba(140, 170, 255, 0.1)", padding: "12px", borderRadius: "12px", background: "rgba(255,255,255,0.01)" }}>
            <h4 style={{ margin: "0 0 6px 0", color: "var(--accent)", fontSize: "0.9rem" }}>Metadata Analysis</h4>
            <div style={{ maxHeight: "150px", overflowY: "auto", fontSize: "0.8rem" }}>
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <tbody>
                  {exifKeys.map((key) => (
                    <tr key={key} style={{ borderBottom: "1px solid rgba(255,255,255,0.05)" }}>
                      <td style={{ padding: "4px 8px 4px 0", color: "var(--muted)", fontWeight: "bold" }}>{key}</td>
                      <td style={{ padding: "4px 0", wordBreak: "break-all" }}>{String(exifMetadata[key])}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Dynamic Sandbox */}
        {sandbox && sandbox.executed && (
          <div className="analyzerCard" style={{ border: "1px solid rgba(140, 170, 255, 0.1)", padding: "12px", borderRadius: "12px", background: "rgba(255,255,255,0.01)" }}>
            <h4 style={{ margin: "0 0 6px 0", color: "var(--accent)", fontSize: "0.9rem" }}>Dynamic Sandbox</h4>
            <p style={{ margin: 0, fontSize: "0.85rem" }}>
              Verdict: <strong style={{ color: sandbox.verdict === "malicious" ? "var(--bad)" : sandbox.verdict === "suspicious" ? "var(--warn)" : "inherit" }}>
                {sandbox.verdict ? sandbox.verdict.toUpperCase() : "NOT RUN"}
              </strong>
            </p>
            {sandbox.reason && <p style={{ margin: "4px 0 0 0", fontSize: "0.8rem", color: "var(--muted)", fontStyle: "italic" }}>{sandbox.reason}</p>}
            {sandbox.details && <p style={{ margin: "4px 0 0 0", fontSize: "0.8rem", color: "var(--muted)" }}>{sandbox.details}</p>}
            {sandbox.behavior_alerts && sandbox.behavior_alerts.length > 0 && (
              <div style={{ marginTop: "8px" }}>
                <p style={{ margin: "0 0 4px 0", fontSize: "0.8rem", fontWeight: "bold", color: "var(--bad)" }}>Behavior Alerts:</p>
                <ul style={{ margin: 0, paddingLeft: "16px", fontSize: "0.8rem" }}>
                  {sandbox.behavior_alerts.map((alert, idx) => (
                    <li key={idx} style={{ color: "var(--bad)" }}>
                      {alert}
                    </li>
                  ))}
                </ul>
              </div>
            )}
            {sandbox.logs && (
              <div style={{ marginTop: "12px" }}>
                <p style={{ margin: "0 0 4px 0", fontSize: "0.8rem", fontWeight: "bold" }}>Execution Logs:</p>
                <pre style={{
                  margin: 0,
                  padding: "8px",
                  background: "rgba(0,0,0,0.3)",
                  borderRadius: "6px",
                  fontSize: "0.75rem",
                  maxHeight: "120px",
                  overflowY: "auto",
                  color: "var(--muted)",
                  whiteSpace: "pre-wrap"
                }}>{sandbox.logs}</pre>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function ZipExplorer({ items, uploadId, onParentRefresh }) {
  const [explorerState, setExplorerState] = useState(() => {
    const cached = readZipExplorerSession(uploadId);
    return cached || {
      tree: null,
      expandedDirs: {},
      selectedFile: null,
      fileContent: null,
      loadingFile: false,
      fileError: null,
    };
  });

  const tree = explorerState.tree;
  const expandedDirs = explorerState.expandedDirs;
  const selectedFile = explorerState.selectedFile;
  const fileContent = explorerState.fileContent;
  const loadingFile = explorerState.loadingFile;
  const fileError = explorerState.fileError;

  // Persist to session storage whenever state changes
  useEffect(() => {
    if (uploadId) {
      writeZipExplorerSession(uploadId, explorerState);
    }
  }, [uploadId, explorerState]);

  // Build tree structure from files
  useEffect(() => {
    if (items) {
      setExplorerState((prev) => ({
        ...prev,
        tree: buildTree(items),
      }));
    }
  }, [items]);

  const toggleDir = (fullName) => {
    setExplorerState((prev) => ({
      ...prev,
      expandedDirs: {
        ...prev.expandedDirs,
        [fullName]: prev.expandedDirs[fullName] === false ? true : false,
      },
    }));
  };

  const handleSelectFile = async (node) => {
    setExplorerState((prev) => ({
      ...prev,
      selectedFile: node,
      fileContent: null,
      fileError: null,
      loadingFile: true,
    }));

    try {
      const res = await fetch(`/api/preview/${uploadId}/zip-file?file_path=${encodeURIComponent(node.fullName)}`);
      const data = await res.json();
      if (!res.ok) {
        setExplorerState((prev) => ({
          ...prev,
          fileError: data.error || "Failed to load preview.",
          loadingFile: false,
        }));
        return;
      }

      setExplorerState((prev) => ({
        ...prev,
        fileContent: data,
        loadingFile: false,
      }));

      if (data.scan_results && (data.scan_results.verdict === "malicious" || data.scan_results.verdict === "suspicious")) {
        onParentRefresh?.();
      }
    } catch (err) {
      setExplorerState((prev) => ({
        ...prev,
        fileError: "Network error: failed to fetch file content.",
        loadingFile: false,
      }));
    }
  };

  if (!tree) {
    return <p>Building directory structure...</p>;
  }

  const ext = selectedFile ? "." + selectedFile.name.split(".").pop().toLowerCase() : "";
  const previewableExts = new Set([".txt", ".py", ".js", ".json", ".sh", ".ini", ".md", ".csv", ".yaml", ".yml", ".xml", ".html", ".css", ".sql", ".conf", ".cfg", ".ps1"]);
  const isSelectedFilePreviewable = selectedFile && previewableExts.has(ext);

  return (
    <div className="zipExplorer">
      <div className="zipTreePane">
        <div className="zipFileTree">
          <TreeNode
            node={tree}
            onSelectFile={(node) => handleSelectFile(node)}
            selectedFile={selectedFile}
            expandedDirs={expandedDirs}
            toggleDir={toggleDir}
          />
        </div>
      </div>
      <div className="zipContentPane">
        {selectedFile ? (
          <>
            <div className="zipContentPaneHeader">
              <div>
                <h5>{selectedFile.fullName}</h5>
                {selectedFile.size !== null && selectedFile.size !== undefined && (
                  <span className="zipContentMeta">
                    Size: {selectedFile.size} bytes
                    {selectedFile.compressed_size !== undefined
                      ? ` / ${selectedFile.compressed_size} bytes compressed`
                      : ""}
                  </span>
                )}
              </div>
            </div>
            {loadingFile ? (
              <div className="sandbox-loading" style={{
                display: "flex",
                flexDirection: "column",
                alignItems: "center",
                justifyContent: "center",
                padding: "40px 20px",
                gap: "16px",
                background: "rgba(140, 170, 255, 0.02)",
                border: "1px dashed rgba(140, 170, 255, 0.15)",
                borderRadius: "12px",
                color: "var(--muted)",
                textAlign: "center"
              }}>
                <div className="spinner">
                  <span></span>
                  <span></span>
                  <span></span>
                  <span></span>
                  <span></span>
                  <span></span>
                  <span></span>
                  <span></span>
                </div>
                <div style={{ marginTop: "12px" }}>
                  <strong style={{ color: "var(--accent)" }}>Extracting & Scanning File...</strong>
                  <p style={{ margin: "6px 0 0 0", fontSize: "0.85rem" }}>
                    SafeGate is spinning up an isolated container to scan patterns and verify dynamic behavior (may take up to 10 seconds).
                  </p>
                </div>
              </div>
            ) : fileError ? (
              <p style={{ color: "var(--bad)" }}>{fileError}</p>
            ) : (
              <>
                {selectedFile.isPotentialZipSlip && (
                  <div className="binary-warning" style={{ marginBottom: "16px", borderColor: "rgba(255, 75, 75, 0.6)", background: "rgba(255, 75, 75, 0.08)" }}>
                    <span className="binary-warning-icon" style={{ color: "#ff4444" }}>⚠️</span>
                    <span className="binary-warning-title" style={{ color: "#ff8888" }}>Zip Slip / Directory Traversal Threat Detected</span>
                    <span className="binary-warning-desc" style={{ color: "#ffbaba" }}>
                      This file path uses directory traversal sequences (like <code>../</code>) to target locations outside the extraction boundary. If extracted by a vulnerable system, this could overwrite critical application or system files, enabling Remote Code Execution (RCE).
                    </span>
                  </div>
                )}
                {!isSelectedFilePreviewable ? (
                  <div className="binary-warning" style={{ marginBottom: "16px" }}>
                    <span className="binary-warning-icon">⚠️</span>
                    <span className="binary-warning-title">Inline Preview Disabled</span>
                    <span className="binary-warning-desc">
                      For security reasons, inline previews are disabled for binary files (e.g., executables, images, or compressed folders).
                    </span>
                  </div>
                ) : fileContent ? (
                  <pre
                    className="zipFileContent"
                    dangerouslySetInnerHTML={{ __html: fileContent.content }}
                  />
                ) : null}
                {fileContent && fileContent.scan_results && renderZipItemScanResults(fileContent.scan_results)}
                {fileContent && (
                  <GeminiZipItemAssistant
                    filePath={selectedFile.fullName}
                    content={fileContent.content}
                    scanResults={fileContent.scan_results}
                    title="Gemini File Explanation"
                  />
                )}
              </>
            )}
          </>
        ) : (
          <div className="zip-explorer-empty">
            <span className="zip-explorer-empty-icon">📂</span>
            <p>Select a file from the explorer pane to preview its contents safely.</p>
          </div>
        )}
      </div>
    </div>
  );
}

function PreviewPanel({ preview, previewState, onParentRefresh }) {
  if (previewState === "loading") {
    return <p>Generating safe preview...</p>;
  }

  if (previewState === "error") {
    return <p>{preview?.error ?? "Preview generation failed."}</p>;
  }

  if (!preview && previewState !== "done") {
    return null;
  }

  if (preview?.preview_kind === "renderable-file" && preview.preview_url) {
    const contentType = preview.content_type || "";
    if (contentType.startsWith("image/")) {
      return <img className="previewMedia" src={preview.preview_url} alt={preview.preview_title} />;
    }
    if (contentType.startsWith("video/")) {
      return <video className="previewMedia" controls src={preview.preview_url} />;
    }
    if (contentType.startsWith("audio/")) {
      return <audio className="previewAudio" controls src={preview.preview_url} />;
    }
    return (
      <iframe
        className="previewFrame"
        src={preview.preview_url}
        title={preview.preview_title}
      />
    );
  }

  if (preview?.preview_kind === "html-screenshot" && preview.preview_url) {
    return (
      <div className="previewStructured">
        <h4>Rendered Sandbox Preview</h4>
        <p style={{ color: "#94a3b8", fontSize: "0.875rem", marginBottom: "1rem" }}>
          This screenshot shows a secure, headless browser rendering of the HTML page inside our sandbox container.
        </p>
        <img 
          className="previewMedia" 
          src={preview.preview_url} 
          alt="HTML Sandbox Screenshot Preview" 
          style={{ 
            border: "1px solid #334155", 
            borderRadius: "0.5rem", 
            maxWidth: "100%", 
            boxShadow: "0 10px 15px -3px rgba(0, 0, 0, 0.5)" 
          }} 
        />
      </div>
    );
  }

  if (preview?.preview_kind === "archive-listing") {
    return (
      <div className="previewStructured">
        <h4>{preview?.preview_title ?? "Safe preview"}</h4>
        <p>{preview?.summary ?? "Preview not loaded yet."}</p>
        <ZipExplorer
          key={preview.upload_id}
          items={preview.items}
          uploadId={preview.upload_id}
          onParentRefresh={onParentRefresh}
        />
      </div>
    );
  }

  return (
    <div className="previewStructured">
      <h4>{preview?.preview_title ?? "Safe preview"}</h4>
      <p>{preview?.summary ?? "Preview not loaded yet."}</p>
      {preview?.text ? <pre className="previewText">{preview.text}</pre> : null}
      {preview?.items?.length ? (
        <div className="previewItems">
          <p>Preview items:</p>
          <ul>
            {preview.items.map((item) => (
              <li key={item.name}>
                <strong>{item.name}</strong>
                <span>
                  {" "}
                  - {item.size} bytes
                  {item.compressed_size !== undefined ? ` / ${item.compressed_size} compressed` : ""}
                </span>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </div>
  );
}

export default function HomePage() {
  const [health, setHealth] = useState("checking");
  const [details, setDetails] = useState(null);
  const [urlInput, setUrlInput] = useState("");
  const [urlState, setUrlState] = useState("idle");
  const [urlResult, setUrlResult] = useState(null);
  const [analysisHistory, setAnalysisHistory] = useState([]);
  const [urlPreviewState, setUrlPreviewState] = useState("idle");
  const [urlPreviewResult, setUrlPreviewResult] = useState(null);
  const [urlDetailsOpen, setUrlDetailsOpen] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const [uploadState, setUploadState] = useState("idle");
  const [uploadResult, setUploadResult] = useState(null);
  const [uploadPreviewState, setUploadPreviewState] = useState("idle");
  const [uploadPreviewResult, setUploadPreviewResult] = useState(null);
  const [uploadDetailsOpen, setUploadDetailsOpen] = useState(false);
  const [reportOpen, setReportOpen] = useState(false);
  const [selectedReportId, setSelectedReportId] = useState(null);
  const [backendUrl, setBackendUrl] = useState("");
  const [toast, setToast] = useState({ show: false, message: "" });

  useEffect(() => {
    async function fetchBackendUrl() {
      try {
        const response = await fetch("/api/backend-url");
        const data = await response.json();
        setBackendUrl(data.url);
      } catch (err) {
        // ignore
      }
    }
    fetchBackendUrl();
  }, []);

  function triggerToast(message) {
    console.log("triggerToast called with:", message);
    let msg = "An unexpected error occurred.";
    if (typeof message === "string") {
      msg = message;
    } else if (message && typeof message.error === "string") {
      msg = message.error;
    } else if (message && typeof message.detail === "string") {
      msg = message.detail;
    } else if (message && Array.isArray(message.detail)) {
      msg = message.detail.map((d) => d.msg).join(", ");
    }
    console.log("Resolved toast message:", msg);
    setToast({ show: true, message: msg });
  }

  useEffect(() => {
    if (toast.show) {
      const timer = setTimeout(() => {
        setToast({ show: false, message: "" });
      }, 10000);
      return () => clearTimeout(timer);
    }
  }, [toast.show]);

  console.log("HomePage render. uploadResult ID:", uploadResult?.upload_id, "uploadPreviewResult:", !!uploadPreviewResult, "urlResult ID:", urlResult?.upload_id, "urlPreviewResult:", !!urlPreviewResult);

  const refreshUploadDetails = async (uploadId) => {
    if (!uploadId) return;
    try {
      const response = await fetch(`/api/upload/${uploadId}`, { cache: "no-store" });
      if (response.ok) {
        const data = await response.json();
        setUploadResult((prev) => prev && prev.upload_id === uploadId ? data : prev);
        setUrlResult((prev) => prev && prev.upload_id === uploadId ? data : prev);
      }
    } catch (err) {
      console.error("Failed to refresh upload details:", err);
    }
  };

  useEffect(() => {
    let cancelled = false;
    let pollInterval = null;
    let slowInterval = null;
    let attempts = 0;

    async function checkHealth() {
      try {
        const response = await fetch("/api/health", { cache: "no-store" });
        const data = await response.json();

        if (!cancelled) {
          if (response.ok) {
            setHealth("online");
            setDetails(data);
            // Clear fast polling once online
            if (pollInterval) {
              clearInterval(pollInterval);
              pollInterval = null;
            }
            // Start slow periodic monitoring every 60s
            if (!slowInterval) {
              slowInterval = setInterval(checkHealth, 60000);
            }
          } else {
            handleFailure();
          }
        }
      } catch (error) {
        if (!cancelled) {
          handleFailure();
        }
      }
    }

    function handleFailure() {
      if (cancelled) return;
      attempts++;
      if (attempts <= 15) {
        // Assume waking up on Render free tier
        setHealth("waking");
        setDetails({ error: "Waiting for backend service to spin up on Render..." });
        // Start fast polling every 5s if not already running
        if (!pollInterval) {
          pollInterval = setInterval(checkHealth, 5000);
        }
      } else {
        // After 15 attempts (~75s), assume truly offline
        setHealth("offline");
        setDetails({ error: "Unable to reach backend health endpoint." });
        if (pollInterval) {
          clearInterval(pollInterval);
          pollInterval = null;
        }
        // Start a slower retry interval (every 30s)
        pollInterval = setInterval(checkHealth, 30000);
      }
    }

    // Run initial health check immediately
    checkHealth();

    return () => {
      cancelled = true;
      if (pollInterval) clearInterval(pollInterval);
      if (slowInterval) clearInterval(slowInterval);
    };
  }, []);

  async function runUrlAnalysis(targetUrl) {
    const normalizedUrl = targetUrl.trim();

    if (!normalizedUrl) {
      setUrlState("missing-url");
      setUrlResult({ error: "Please paste a download link first." });
      triggerToast("Please paste a download link first.");
      return;
    }

    setUrlInput(normalizedUrl);
    setUrlState("analyzing");
    setUrlResult(null);
    setUrlPreviewState("idle");
    setUrlPreviewResult(null);
    setUrlDetailsOpen(false);

    try {
      const response = await fetch("/api/analyze-url", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ url: normalizedUrl }),
      });

      const data = await response.json();

      if (!response.ok) {
        setUrlState("error");
        setUrlResult(data);
        triggerToast(data);
        return;
      }

      if (data.analysis_state === "pending") {
        setUrlState("scanning");
        setUrlResult(data);
        const pollInterval = setInterval(async () => {
          try {
             const pollResponse = await fetch(`/api/upload/${data.upload_id}`, { cache: "no-store" });
             if (!pollResponse.ok) {
               clearInterval(pollInterval);
               setUrlState("error");
               setUrlResult({ error: "Background scanning status check failed." });
               triggerToast("Background scanning status check failed.");
               return;
             }
             const pollData = await pollResponse.json();
             if (pollData.analysis_state !== "pending") {
               clearInterval(pollInterval);
               if (pollData.analysis_state === "failed" || pollData.analysis_state === "error") {
                 setUrlState("error");
                 setUrlResult(pollData);
                 triggerToast(pollData.static_analysis?.error || pollData.error || "Analysis failed.");
               } else {
                 setUrlState("done");
                 setUrlResult(pollData);
                 setAnalysisHistory((previousHistory) => {
                   const nextEntry = {
                     inspected_url: normalizedUrl,
                     analyzed_at: new Date().toISOString(),
                     ...pollData,
                   };
                   const deduped = previousHistory.filter((entry) => entry.inspected_url !== normalizedUrl);
                   return [nextEntry, ...deduped].slice(0, 8);
                 });
               }
             }
          } catch (err) {
            clearInterval(pollInterval);
            setUrlState("error");
            setUrlResult({ error: "Background scanning check connection failed." });
            triggerToast("Background scanning check connection failed.");
          }
        }, 2000);
      } else {
        setUrlState("done");
        setUrlResult(data);
        setAnalysisHistory((previousHistory) => {
          const nextEntry = {
            inspected_url: normalizedUrl,
            analyzed_at: new Date().toISOString(),
            ...data,
          };
          const deduped = previousHistory.filter((entry) => entry.inspected_url !== normalizedUrl);
          return [nextEntry, ...deduped].slice(0, 8);
        });
      }
    } catch (error) {
      setUrlState("error");
      setUrlResult({ error: "URL analysis failed." });
      triggerToast("URL analysis failed.");
    }
  }

  async function handleAnalyzeUrl(event) {
    event.preventDefault();
    await runUrlAnalysis(urlInput);
  }

  async function handleCandidateInspect(candidateUrl) {
    await runUrlAnalysis(candidateUrl);
  }

  function findCandidateAnalysis(candidateUrl) {
    return analysisHistory.find((entry) => entry.inspected_url === candidateUrl);
  }

  async function loadPreview(uploadId, setPreviewState, setPreviewResult) {
    if (!uploadId) {
      setPreviewState("missing-upload");
      setPreviewResult({ error: "No analyzed upload is available yet." });
      return;
    }

    setPreviewState("loading");
    setPreviewResult(null);

    try {
      const response = await fetch("/api/preview", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ upload_id: uploadId }),
      });

      const data = await response.json();

      if (!response.ok) {
        setPreviewState("error");
        setPreviewResult(data);
        return;
      }

      setPreviewState("done");
      setPreviewResult(data);
    } catch (error) {
      setPreviewState("error");
      setPreviewResult({ error: "Preview load failed." });
    }
  }

  async function handleUpload(event) {
    event.preventDefault();

    if (!selectedFile) {
      setUploadState("missing-file");
      setUploadResult({ error: "Please choose a file first." });
      triggerToast("Please choose a file first.");
      return;
    }

    if (selectedFile.size > 50 * 1024 * 1024) {
      setUploadState("error");
      setUploadResult({ error: "File exceeds the 50 MB MVP upload limit." });
      triggerToast("File exceeds the 50 MB MVP upload limit.");
      return;
    }

    setUploadState("uploading");
    setUploadResult(null);
    setUploadPreviewState("idle");
    setUploadPreviewResult(null);
    setUploadDetailsOpen(false);

    const formData = new FormData();
    formData.append("file", selectedFile);

    try {
      const response = await fetch("/api/upload", {
        method: "POST",
        body: formData,
      });

      const data = await response.json();

      if (!response.ok) {
        setUploadState("error");
        setUploadResult(data);
        triggerToast(data);
        return;
      }

      if (data.analysis_state === "pending") {
        setUploadState("scanning");
        setUploadResult(data);
        const pollInterval = setInterval(async () => {
          try {
            const pollResponse = await fetch(`/api/upload/${data.upload_id}`, { cache: "no-store" });
            if (!pollResponse.ok) {
              clearInterval(pollInterval);
              setUploadState("error");
              setUploadResult({ error: "Background scanning status check failed." });
              triggerToast("Background scanning status check failed.");
              return;
            }
            const pollData = await pollResponse.json();
             if (pollData.analysis_state !== "pending") {
               clearInterval(pollInterval);
               if (pollData.analysis_state === "failed" || pollData.analysis_state === "error") {
                 setUploadState("error");
                 setUploadResult(pollData);
                 triggerToast(pollData.static_analysis?.error || pollData.error || "Analysis failed.");
               } else {
                 setUploadState("done");
                 setUploadResult(pollData);
               }
             }
          } catch (err) {
            clearInterval(pollInterval);
            setUploadState("error");
            setUploadResult({ error: "Background scanning check connection failed." });
            triggerToast("Background scanning check connection failed.");
          }
        }, 2000);
      } else {
        setUploadState("done");
        setUploadResult(data);
      }
    } catch (error) {
      setUploadState("error");
      setUploadResult({ error: "Upload failed." });
      triggerToast("Upload failed.");
    }
  }

  return (
    <main className="shell">
      <section className="hero">
        <div className="badge">SafeGate MVP</div>
        <h1>Inspect suspicious download links before they reach your laptop.</h1>
        <p className="lede">
          SafeGate is the first step toward a safer download workflow: link,
          inspect, preview, decide.
        </p>

        <div className="statusCard">
          <div className="statusHeader" style={{ display: "flex", flexDirection: "column", alignItems: "flex-start", gap: "8px", marginBottom: 0 }}>
            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <span className={`dot ${health === "checking" || health === "waking" ? "warn" : health}`} />
              <span>
                Backend status:{" "}
                {health === "waking"
                  ? "waking up scanner service..."
                  : health === "checking"
                  ? "checking..."
                  : health}
              </span>
            </div>
            {health === "waking" && backendUrl && (
              <span style={{ fontSize: "0.85rem", color: "var(--muted)", marginLeft: "20px" }}>
                Render's free tier sleeps after 15m of inactivity. If it's taking too long,{" "}
                <a href={`${backendUrl}/health`} target="_blank" rel="noreferrer" style={{ color: "var(--accent)", textDecoration: "underline" }}>
                  click here to force wake it up
                </a>.
              </span>
            )}
          </div>
        </div>

        <form className="uploadCard" onSubmit={handleAnalyzeUrl} key="url-form">
          <div className="statusHeader">
            <span className={`dot ${urlState === "done" ? "online" : urlState === "error" || urlState === "missing-url" ? "error" : "warn"}`} />
            <span>Link analysis: {urlState}</span>
          </div>
          <label className="fileLabel">
            Paste a suspicious download link
            <input
              type="url"
              placeholder={health === "online" ? "https://example.com/download/file" : "Backend offline, waiting..."}
              value={urlInput}
              onChange={(event) => setUrlInput(event.target.value)}
              disabled={health !== "online"}
            />
          </label>
          <button type="submit" className="uiverseButton analyzeButton" disabled={health !== "online"}>
            <span className="uiverseButtonLg">
              <span className="uiverseButtonSl" />
              <span className="uiverseButtonText">
                {health === "online" ? "Analyze Link" : "Waiting for backend..."}
              </span>
            </span>
          </button>
          {(urlState === "analyzing" || urlState === "scanning") && (
            <div className="downloadProgressBarContainer" style={{
              marginTop: "20px",
              marginBottom: "20px",
              padding: "16px",
              background: "rgba(140, 170, 255, 0.04)",
              border: "1px solid rgba(140, 170, 255, 0.1)",
              borderRadius: "14px",
              display: "flex",
              alignItems: "center",
              gap: "24px",
              boxShadow: "inset 0 1px 1px rgba(255, 255, 255, 0.05)"
            }}>
              <div style={{ width: "120px", display: "flex", justifyContent: "center", alignItems: "center", flexShrink: 0 }}>
                <div className="spinner">
                  <span></span>
                  <span></span>
                  <span></span>
                  <span></span>
                  <span></span>
                  <span></span>
                  <span></span>
                  <span></span>
                </div>
              </div>
              <div style={{ flexGrow: 1 }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
                  <span style={{ fontSize: "0.9rem", fontWeight: "600", color: "var(--accent)" }}>
                    {urlState === "analyzing"
                      ? "Initiating connection..."
                      : (urlResult?.source_state === "pending_fetch"
                        ? (urlResult?.download_progress !== undefined && urlResult?.download_progress !== null && urlResult.download_progress >= 0
                          ? "Downloading file to container..."
                          : "Connecting & downloading remote file...")
                        : "Running security checks (ClamAV, YARA, ExifTool, Sandbox)...")}
                  </span>
                  <span style={{ fontSize: "0.85rem", fontWeight: "bold", color: "var(--muted)", background: "rgba(255,255,255,0.05)", padding: "2px 8px", borderRadius: "8px" }}>
                    {urlState === "scanning" && urlResult?.source_state === "pending_fetch" && urlResult?.download_progress !== undefined && urlResult?.download_progress !== null && urlResult.download_progress >= 0
                      ? `${urlResult.download_progress}%`
                      : "Scanning..."}
                  </span>
                </div>
                <div className="loader" style={{ width: "100%" }}></div>
              </div>
            </div>
          )}
          {urlResult?.upload_id ? (
            <button
              key="url-preview-btn"
              type="button"
              className="ui-btn previewButton"
              onClick={() => loadPreview(urlResult.upload_id, setUrlPreviewState, setUrlPreviewResult)}
            >
              <span>Load Safe Preview</span>
            </button>
          ) : null}
          {urlResult ? (
            <div className="detailsToggle" key="url-details-toggle" style={{ display: "flex", gap: "12px", flexWrap: "wrap", marginTop: "16px" }}>
              <button
                type="button"
                className="ui-btn detailButton detailsToggleButton"
                onClick={() => setUrlDetailsOpen((previous) => !previous)}
              >
                <span>{urlDetailsOpen ? "Hide details" : "View more details"}</span>
              </button>
              {urlResult?.upload_id && (
                <button
                  type="button"
                  className="ui-btn previewButton"
                  onClick={() => {
                    setSelectedReportId(urlResult.upload_id);
                    setReportOpen(true);
                  }}
                >
                  <span>View Security Report</span>
                </button>
              )}
              {urlDetailsOpen ? <pre style={{ width: "100%" }}>{JSON.stringify(urlResult, null, 2)}</pre> : null}
            </div>
          ) : null}
          {urlResult?.source_state ? (
            <div className="fingerprintSummary" key="url-source-summary">
              <h3>Source summary</h3>
              <p>
                Source kind: <strong>{urlResult.source_kind}</strong>
              </p>
              <p>
                Source state: <strong>{urlResult.source_state}</strong>
              </p>
              {urlResult.notes?.length ? (
                <div className="candidateList">
                  <p>Notes:</p>
                  <ul>
                    {urlResult.notes.map((note) => (
                      <li key={note}>{note}</li>
                    ))}
                  </ul>
                </div>
              ) : null}
              {urlResult.source_state === "landing_page" ? (
                <p>This link looks like a webpage. SafeGate found candidate download links for comparison.</p>
              ) : null}
              {urlResult.source_state === "landing_page_followed" ? (
                <p>
                  SafeGate found a landing page, followed the best candidate download link, and analyzed the
                  fetched file.
                </p>
              ) : null}
              {urlResult.selected_candidate_url ? (
                <p>
                  Selected candidate:{" "}
                  <strong>{urlResult.selected_candidate_url}</strong>
                </p>
              ) : null}
            </div>
          ) : null}
          {urlResult?.candidate_details?.length ? (
            <div className="fingerprintSummary" key="url-compare-candidates">
              <h3>Compare candidates</h3>
              <p>Inspect each candidate and compare scores, reasons, and analysis results.</p>
              <div className="candidateCompareTable">
                <div className="candidateCompareHead">
                  <span>#</span>
                  <span>Candidate</span>
                  <span>Score</span>
                  <span>Reasons</span>
                  <span>Status</span>
                  <span>Actions</span>
                </div>
                {urlResult.candidate_details.map((candidate, index) => {
                  const inspectedCandidate = findCandidateAnalysis(candidate.url);
                  const isSelectedCandidate = urlResult.selected_candidate_url === candidate.url;
                  return (
                    <div className="candidateCompareRow" key={candidate.url}>
                      <span>{index + 1}</span>
                      <span className="candidateUrlCell">{candidate.url}</span>
                      <span>{candidate.score}</span>
                      <span>{candidate.reasons?.length ? candidate.reasons.join(", ") : "none"}</span>
                      <span>
                        {isSelectedCandidate ? "selected" : inspectedCandidate ? "inspected" : "pending"}
                      </span>
                      <span className="candidateActions">
                        <button type="button" className="adamgieblButton inspectButton" onClick={() => handleCandidateInspect(candidate.url)}>
                          <div className="svgWrapper1">
                            <div className="svgWrapper">
                              <svg
                                xmlns="http://www.w3.org/2000/svg"
                                viewBox="0 0 24 24"
                                width="24"
                                height="24"
                              >
                                <path fill="none" d="M0 0h24v24H0z"></path>
                                <path
                                  fill="currentColor"
                                  d="M1.946 9.315c-.522-.174-.527-.455.01-.634l19.087-6.362c.529-.176.832.12.684.638l-5.454 19.086c-.15.529-.455.547-.679.045L12 14l6-8-8 6-8.054-2.685z"
                                ></path>
                              </svg>
                            </div>
                          </div>
                          <span>Inspect</span>
                        </button>{" "}
                        <a href={candidate.url} target="_blank" rel="noreferrer">
                          Open
                        </a>
                      </span>
                    </div>
                  );
                })}
              </div>
              {analysisHistory.length ? (
                <div className="candidateHistory">
                  <p>Recent inspections</p>
                  <ul>
                    {analysisHistory.map((entry) => (
                      <li key={`${entry.inspected_url}-${entry.analyzed_at}`}>
                        <strong>{entry.inspected_url}</strong>
                        <span>
                          {" "}
                          - {entry.source_state} - {entry.fingerprint?.match_status ?? "n/a"} -{" "}
                          {entry.fingerprint?.detected_content_type ?? "unknown"}
                        </span>
                      </li>
                    ))}
                  </ul>
                </div>
              ) : null}
            </div>
          ) : null}
          {urlResult ? (
            <div key="url-static-analysis">
              {renderStaticAnalysis(urlResult)}
            </div>
          ) : null}
          {urlResult?.fingerprint ? (
            <div className="fingerprintSummary" key="url-fingerprint">
              <h3>Fingerprint summary</h3>
              <p>
                Claimed: <strong>{urlResult.fingerprint.claimed_content_type}</strong>
              </p>
              <p>
                Detected: <strong>{urlResult.fingerprint.detected_content_type}</strong>
              </p>
              <p>
                Match status: <strong>{urlResult.fingerprint.match_status}</strong>
              </p>
              <p>
                Confidence: <strong>{urlResult.fingerprint.confidence}</strong>
              </p>
            </div>
          ) : null}
          {urlPreviewResult || urlPreviewState !== "idle" ? (
            <div className="fingerprintSummary" key="url-safe-preview">
              <h3>Safe preview</h3>
              <p>Preview state: <strong>{urlPreviewState}</strong></p>
              {urlPreviewResult?.preview_kind ? (
                <p>
                  Preview kind: <strong>{urlPreviewResult.preview_kind}</strong>
                </p>
              ) : null}
              {urlPreviewResult?.preview_url ? (
                <p>
                  Preview URL:{" "}
                  <a href={urlPreviewResult.preview_url} target="_blank" rel="noreferrer">
                    Open preview in a new tab
                  </a>
                </p>
              ) : null}
              <PreviewPanel
                preview={urlPreviewResult}
                previewState={urlPreviewState}
                onParentRefresh={() => refreshUploadDetails(urlResult?.upload_id)}
              />
            </div>
          ) : null}
        </form>
        {urlResult ? (
          <GeminiAssistant
            key="url-gemini-assistant"
            title="Gemini explanation and chat"
            analysis={{ ...urlResult, preview: urlPreviewResult }}
            analysisKey={urlResult.upload_id || urlResult.error || urlResult.detail || "url-error"}
          />
        ) : null}

        <form className="uploadCard fallbackCard" onSubmit={handleUpload} key="upload-form">
          <div className="statusHeader">
            <span className={`dot ${uploadState === "done" ? "online" : uploadState === "error" || uploadState === "missing-file" ? "error" : "warn"}`} />
            <span>Fallback upload: {uploadState}</span>
          </div>
          <label className="fileLabel">
            Upload a file directly if needed
            <input
              type="file"
              onChange={(event) => setSelectedFile(event.target.files?.[0] ?? null)}
              disabled={health !== "online"}
            />
          </label>
          <button type="submit" className="uiverseButton analyzeButton" disabled={health !== "online"}>
            <span className="uiverseButtonLg">
              <span className="uiverseButtonSl" />
              <span className="uiverseButtonText">
                {health === "online" ? "Upload File" : "Waiting for backend..."}
              </span>
            </span>
          </button>
          {(uploadState === "uploading" || uploadState === "scanning") && (
            <div className="downloadProgressBarContainer" key="upload-loader" style={{
              marginTop: "20px",
              marginBottom: "20px",
              padding: "16px",
              background: "rgba(140, 170, 255, 0.04)",
              border: "1px solid rgba(140, 170, 255, 0.1)",
              borderRadius: "14px",
              display: "flex",
              alignItems: "center",
              gap: "24px",
              boxShadow: "inset 0 1px 1px rgba(255, 255, 255, 0.05)"
            }}>
              <div style={{ width: "120px", display: "flex", justifyContent: "center", alignItems: "center", flexShrink: 0 }}>
                <div className="spinner">
                  <span></span>
                  <span></span>
                  <span></span>
                  <span></span>
                  <span></span>
                  <span></span>
                  <span></span>
                  <span></span>
                </div>
              </div>
              <div style={{ flexGrow: 1 }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
                  <span style={{ fontSize: "0.9rem", fontWeight: "600", color: "var(--accent)" }}>
                    {uploadState === "uploading"
                      ? "Uploading file to server..."
                      : "Running security checks (ClamAV, YARA, ExifTool, Sandbox)..."}
                  </span>
                  <span style={{ fontSize: "0.85rem", fontWeight: "bold", color: "var(--muted)", background: "rgba(255,255,255,0.05)", padding: "2px 8px", borderRadius: "8px" }}>
                    {uploadState === "uploading" ? "Uploading..." : "Scanning..."}
                  </span>
                </div>
                <div className="loader" style={{ width: "100%" }}></div>
              </div>
            </div>
          )}
          {uploadResult?.upload_id ? (
            <button
              key="upload-preview-btn"
              type="button"
              className="ui-btn previewButton"
              onClick={() => loadPreview(uploadResult.upload_id, setUploadPreviewState, setUploadPreviewResult)}
            >
              <span>Load Safe Preview</span>
            </button>
          ) : null}
          {uploadResult ? (
            <div className="detailsToggle" key="upload-details-toggle" style={{ display: "flex", gap: "12px", flexWrap: "wrap", marginTop: "16px" }}>
              <button
                type="button"
                className="ui-btn detailButton detailsToggleButton"
                onClick={() => setUploadDetailsOpen((previous) => !previous)}
              >
                <span>{uploadDetailsOpen ? "Hide details" : "View more details"}</span>
              </button>
              {uploadResult?.upload_id && (
                <button
                  type="button"
                  className="ui-btn previewButton"
                  onClick={() => {
                    setSelectedReportId(uploadResult.upload_id);
                    setReportOpen(true);
                  }}
                >
                  <span>View Security Report</span>
                </button>
              )}
              {uploadDetailsOpen ? <pre style={{ width: "100%" }}>{JSON.stringify(uploadResult, null, 2)}</pre> : null}
            </div>
          ) : null}
          {uploadResult ? (
            <div key="upload-static-analysis">
              {renderStaticAnalysis(uploadResult)}
            </div>
          ) : null}
          {uploadResult?.fingerprint ? (
            <div className="fingerprintSummary" key="upload-fingerprint">
              <h3>Fingerprint summary</h3>
              <p>
                Claimed: <strong>{uploadResult.fingerprint.claimed_content_type}</strong>
              </p>
              <p>
                Detected: <strong>{uploadResult.fingerprint.detected_content_type}</strong>
              </p>
              <p>
                Match status: <strong>{uploadResult.fingerprint.match_status}</strong>
              </p>
              <p>
                Confidence: <strong>{uploadResult.fingerprint.confidence}</strong>
              </p>
            </div>
          ) : null}
          {uploadPreviewResult || uploadPreviewState !== "idle" ? (
            <div className="fingerprintSummary" key="upload-safe-preview">
              <h3>Safe preview</h3>
              <p>Preview state: <strong>{uploadPreviewState}</strong></p>
              {uploadPreviewResult?.preview_kind ? (
                <p>
                  Preview kind: <strong>{uploadPreviewResult.preview_kind}</strong>
                </p>
              ) : null}
              {uploadPreviewResult?.preview_url ? (
                <p>
                  Preview URL:{" "}
                  <a href={uploadPreviewResult.preview_url} target="_blank" rel="noreferrer">
                    Open preview in a new tab
                  </a>
                </p>
              ) : null}
              <PreviewPanel
                preview={uploadPreviewResult}
                previewState={uploadPreviewState}
                onParentRefresh={() => refreshUploadDetails(uploadResult?.upload_id)}
              />
            </div>
          ) : null}
          {uploadResult?.error === "File exceeds the 50 MB MVP upload limit." && 
           typeof window !== "undefined" && 
           (window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1") && (
            <div style={{
              marginTop: "20px",
              padding: "18px",
              background: "rgba(59, 130, 246, 0.05)",
              border: "1px solid rgba(59, 130, 246, 0.25)",
              borderRadius: "12px",
              textAlign: "left",
              fontSize: "0.88rem",
              lineHeight: "1.5",
              boxShadow: "0 4px 20px rgba(0, 0, 0, 0.15)"
            }}>
              <strong style={{ color: "#f87171", display: "block", marginBottom: "10px", fontSize: "0.95rem" }}>
                ⚠️ CRITICAL SAFETY NOTE: Do NOT open or execute this file before testing it!
              </strong>
              <span style={{ color: "var(--muted)", display: "block", marginBottom: "12px" }}>
                Because you are running SafeGate locally, you can scan files larger than 50 MB (up to 2 GB+) directly using the dockerized scan engines. Copy the file into your local <code>SafeGate/storage/</code> folder and run the following in your terminal:
              </span>
              <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
                <div>
                  <strong style={{ color: "#93c5fd", display: "block", fontSize: "0.82rem", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: "4px" }}>1. Scan with ClamAV</strong>
                  <code style={{ background: "rgba(0, 0, 0, 0.4)", color: "#e2e8f0", padding: "6px 10px", borderRadius: "6px", display: "block", fontFamily: "monospace", fontSize: "0.8rem", border: "1px solid rgba(255,255,255,0.05)" }}>
                    docker compose exec backend clamscan /app/storage/{selectedFile?.name || "your_file"}
                  </code>
                </div>
                <div>
                  <strong style={{ color: "#93c5fd", display: "block", fontSize: "0.82rem", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: "4px" }}>2. Scan with YARA</strong>
                  <code style={{ background: "rgba(0, 0, 0, 0.4)", color: "#e2e8f0", padding: "6px 10px", borderRadius: "6px", display: "block", fontFamily: "monospace", fontSize: "0.8rem", border: "1px solid rgba(255,255,255,0.05)" }}>
                    docker compose exec backend yara /app/analyzers/rules.yar /app/storage/{selectedFile?.name || "your_file"}
                  </code>
                </div>
                <div>
                  <strong style={{ color: "#93c5fd", display: "block", fontSize: "0.82rem", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: "4px" }}>3. Dynamic Sandbox (Python)</strong>
                  <code style={{ background: "rgba(0, 0, 0, 0.4)", color: "#e2e8f0", padding: "6px 10px", borderRadius: "6px", display: "block", fontFamily: "monospace", fontSize: "0.8rem", border: "1px solid rgba(255,255,255,0.05)" }}>
                    docker run --rm --network none --memory 2g -v C:\Users\DELL\Downloads\SafeGate\storage:/sandbox python:3.10-slim python /sandbox/{selectedFile?.name || "your_file"}
                  </code>
                </div>
              </div>
            </div>
          )}
        </form>
        {uploadResult ? (
          <GeminiAssistant
            key="upload-gemini-assistant"
            title="Gemini explanation and chat"
            analysis={{ ...uploadResult, preview: uploadPreviewResult }}
            analysisKey={uploadResult.upload_id || uploadResult.error || uploadResult.detail || "upload-error"}
          />
        ) : null}
      </section>




      <footer style={{
        marginTop: "40px",
        padding: "24px 0",
        borderTop: "1px solid var(--panel-border)",
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
        flexWrap: "wrap",
        gap: "12px",
        color: "var(--muted)",
        fontSize: "0.9rem"
      }}>
        <span>&copy; {new Date().getFullYear()} SafeGate. All rights reserved.</span>
        <div style={{ display: "flex", gap: "20px" }}>
          <Link href="/terms" style={{ color: "var(--muted)", textDecoration: "none" }}>
            Terms of Service
          </Link>
          <Link href="/privacy" style={{ color: "var(--muted)", textDecoration: "none" }}>
            Privacy Policy
          </Link>
        </div>
      </footer>
      {reportOpen && (
        <SecurityReport 
          uploadId={selectedReportId} 
          onClose={() => {
            setReportOpen(false);
            setSelectedReportId(null);
          }} 
        />
      )}
      {toast.show && (
        <div style={{
          position: "fixed",
          bottom: "24px",
          left: "50%",
          transform: "translateX(-50%)",
          backgroundColor: "rgba(15, 23, 42, 0.95)",
          backdropFilter: "blur(8px)",
          border: "1px solid rgba(239, 68, 68, 0.35)",
          color: "#fff",
          padding: "14px 20px",
          borderRadius: "12px",
          boxShadow: "0 10px 30px rgba(0, 0, 0, 0.5), 0 0 15px rgba(239, 68, 68, 0.1)",
          zIndex: 9999,
          display: "flex",
          alignItems: "center",
          gap: "16px",
          maxWidth: "500px",
          width: "90%",
          animation: "fadeInUp 0.3s ease-out",
        }}>
          <span style={{ fontSize: "1.25rem", color: "#ef4444", flexShrink: 0 }}>⚠️</span>
          <div style={{ flexGrow: 1, fontSize: "0.9rem", lineHeight: "1.4", color: "#f8fafc" }}>
            <strong style={{ color: "#f87171", display: "block", fontSize: "0.85rem", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: "2px" }}>Scan Failed</strong>
            {toast.message}
          </div>
          <button 
            type="button"
            onClick={() => setToast({ show: false, message: "" })}
            style={{
              background: "rgba(255, 255, 255, 0.08)",
              border: "none",
              color: "#cbd5e1",
              cursor: "pointer",
              padding: "6px 12px",
              borderRadius: "6px",
              fontSize: "0.8rem",
              fontWeight: "600",
              transition: "all 0.2s ease",
              outline: "none",
            }}
            onMouseEnter={(e) => {
              e.target.style.background = "rgba(239, 68, 68, 0.2)";
              e.target.style.color = "#fff";
            }}
            onMouseLeave={(e) => {
              e.target.style.background = "rgba(255, 255, 255, 0.08)";
              e.target.style.color = "#cbd5e1";
            }}
          >
            Dismiss
          </button>
        </div>
      )}
    </main>
  );
}
