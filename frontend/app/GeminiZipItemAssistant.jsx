"use client";

import { useEffect, useState } from "react";

export default function GeminiZipItemAssistant({ filePath, content, scanResults, title }) {
  const [explainState, setExplainState] = useState("idle");
  const [explanation, setExplanation] = useState(null);

  useEffect(() => {
    setExplainState("idle");
    setExplanation(null);
  }, [filePath]);

  async function requestExplain() {
    if (!filePath) {
      setExplainState("error");
      setExplanation({ error: "No file selected." });
      return;
    }

    setExplainState("loading");
    setExplanation(null);

    try {
      const response = await fetch("/api/ai/explain-zip-item", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          file_path: filePath,
          content: content || null,
          scan_results: scanResults || null,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        setExplainState("error");
        setExplanation({ error: data.detail || data.error || "Gemini explanation failed." });
        return;
      }

      setExplainState("done");
      setExplanation(data);
    } catch (error) {
      setExplainState("error");
      setExplanation({ error: "Gemini explanation failed." });
    }
  }

  return (
    <div className="fingerprintSummary" style={{ marginTop: "20px", background: "rgba(10, 20, 40, 0.3)", border: "1px solid rgba(140, 170, 255, 0.15)" }}>
      <h3>{title || "AI File Explanation"}</h3>
      <p style={{ fontSize: "0.85rem", color: "var(--muted)", marginBottom: "12px" }}>
        Gemini analyzes the code snippet and safety scans to explain what this file does in simple terms.
      </p>
      <div className="geminiActions" style={{ display: "flex", gap: "12px", alignItems: "center" }}>
        <button type="button" onClick={requestExplain} className="ui-btn-gemini">
          <div className="button-glow"></div>
          <div className="button-content">
            <span className="sparkle">✦</span>
            <span>Explain with Gemini</span>
          </div>
        </button>
        <span className="geminiState" style={{ fontSize: "0.8rem", color: "var(--muted)" }}>
          State: {explainState.toUpperCase()}
        </span>
      </div>
      {explanation?.answer ? (
        <div className="geminiAnswer" style={{ marginTop: "12px", padding: "12px", background: "rgba(255, 255, 255, 0.02)", borderRadius: "8px", border: "1px solid rgba(140, 170, 255, 0.1)" }}>
          {explanation.answer.split("\n").map((line, index) => (
            <p key={index} style={{ margin: "4px 0", fontSize: "0.85rem", lineHeight: "1.4" }}>{line}</p>
          ))}
          {explanation.mode === "fallback" ? (
            <p className="geminiFallbackNote" style={{ fontSize: "0.75rem", color: "var(--warn)", marginTop: "6px" }}>
              Gemini is busy right now, so SafeGate used a local fallback summary.
            </p>
          ) : null}
        </div>
      ) : explanation?.error ? (
        <p className="geminiError" style={{ color: "var(--bad)", fontSize: "0.8rem", marginTop: "10px" }}>{explanation.error}</p>
      ) : null}
    </div>
  );
}
