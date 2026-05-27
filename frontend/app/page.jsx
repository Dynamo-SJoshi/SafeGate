"use client";

import { useEffect, useState } from "react";

export default function HomePage() {
  const [health, setHealth] = useState("checking");
  const [details, setDetails] = useState(null);
  const [urlInput, setUrlInput] = useState("");
  const [urlState, setUrlState] = useState("idle");
  const [urlResult, setUrlResult] = useState(null);
  const [selectedFile, setSelectedFile] = useState(null);
  const [uploadState, setUploadState] = useState("idle");
  const [uploadResult, setUploadResult] = useState(null);

  useEffect(() => {
    let cancelled = false;

    async function checkHealth() {
      try {
        const response = await fetch("/api/health", { cache: "no-store" });
        const data = await response.json();

        if (!cancelled) {
          setHealth(response.ok ? "online" : "error");
          setDetails(data);
        }
      } catch (error) {
        if (!cancelled) {
          setHealth("offline");
          setDetails({ error: "Unable to reach backend health endpoint." });
        }
      }
    }

    checkHealth();

    return () => {
      cancelled = true;
    };
  }, []);

  async function handleAnalyzeUrl(event) {
    event.preventDefault();

    if (!urlInput.trim()) {
      setUrlState("missing-url");
      setUrlResult({ error: "Please paste a download link first." });
      return;
    }

    setUrlState("analyzing");
    setUrlResult(null);

    try {
      const response = await fetch("/api/analyze-url", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ url: urlInput }),
      });

      const data = await response.json();

      if (!response.ok) {
        setUrlState("error");
        setUrlResult(data);
        return;
      }

      setUrlState("done");
      setUrlResult(data);
    } catch (error) {
      setUrlState("error");
      setUrlResult({ error: "URL analysis failed." });
    }
  }

  async function handleUpload(event) {
    event.preventDefault();

    if (!selectedFile) {
      setUploadState("missing-file");
      setUploadResult({ error: "Please choose a file first." });
      return;
    }

    setUploadState("uploading");
    setUploadResult(null);

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
        return;
      }

      setUploadState("done");
      setUploadResult(data);
    } catch (error) {
      setUploadState("error");
      setUploadResult({ error: "Upload failed." });
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
          <div className="statusHeader">
            <span className={`dot ${health}`} />
            <span>Backend status: {health}</span>
          </div>
          <pre>{JSON.stringify(details, null, 2)}</pre>
        </div>

        <form className="uploadCard" onSubmit={handleAnalyzeUrl}>
          <div className="statusHeader">
            <span className={`dot ${urlState === "done" ? "online" : urlState === "error" || urlState === "missing-url" ? "error" : "warn"}`} />
            <span>Link analysis: {urlState}</span>
          </div>
          <label className="fileLabel">
            Paste a suspicious download link
            <input
              type="url"
              placeholder="https://example.com/download/file"
              value={urlInput}
              onChange={(event) => setUrlInput(event.target.value)}
            />
          </label>
          <button type="submit">Analyze Link</button>
          <pre>{JSON.stringify(urlResult, null, 2)}</pre>
          {urlResult?.fingerprint ? (
            <div className="fingerprintSummary">
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
        </form>

        <form className="uploadCard fallbackCard" onSubmit={handleUpload}>
          <div className="statusHeader">
            <span className={`dot ${uploadState === "done" ? "online" : uploadState === "error" || uploadState === "missing-file" ? "error" : "warn"}`} />
            <span>Fallback upload: {uploadState}</span>
          </div>
          <label className="fileLabel">
            Upload a file directly if needed
            <input
              type="file"
              onChange={(event) => setSelectedFile(event.target.files?.[0] ?? null)}
            />
          </label>
          <button type="submit">Upload File</button>
          <pre>{JSON.stringify(uploadResult, null, 2)}</pre>
          {uploadResult?.fingerprint ? (
            <div className="fingerprintSummary">
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
        </form>
      </section>

      <section className="grid">
        <article className="panel">
          <h2>What this frontend does</h2>
          <ul>
            <li>Shows the SafeGate landing page</li>
            <li>Checks the backend health endpoint</li>
            <li>Lets you paste a download link for analysis</li>
            <li>Keeps file upload as a fallback</li>
          </ul>
        </article>

        <article className="panel">
          <h2>Next UI milestones</h2>
          <ul>
            <li>Show link analysis metadata after submission</li>
            <li>Scan progress state</li>
            <li>Result / risk report page</li>
            <li>Temporary preview screen</li>
            <li>Browser extension integration later</li>
          </ul>
        </article>
      </section>
    </main>
  );
}
