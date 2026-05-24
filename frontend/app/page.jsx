"use client";

import { useEffect, useState } from "react";

export default function HomePage() {
  const [health, setHealth] = useState("checking");
  const [details, setDetails] = useState(null);
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
        <h1>Inspect suspicious downloads before they reach your laptop.</h1>
        <p className="lede">
          SafeGate is the first step toward a safer download workflow: upload,
          inspect, preview, decide.
        </p>

        <div className="statusCard">
          <div className="statusHeader">
            <span className={`dot ${health}`} />
            <span>Backend status: {health}</span>
          </div>
          <pre>{JSON.stringify(details, null, 2)}</pre>
        </div>

        <form className="uploadCard" onSubmit={handleUpload}>
          <div className="statusHeader">
            <span className={`dot ${uploadState === "done" ? "online" : uploadState === "error" || uploadState === "missing-file" ? "error" : "warn"}`} />
            <span>Upload state: {uploadState}</span>
          </div>
          <label className="fileLabel">
            Choose a file to inspect
            <input
              type="file"
              onChange={(event) => setSelectedFile(event.target.files?.[0] ?? null)}
            />
          </label>
          <button type="submit">Upload to SafeGate</button>
          <pre>{JSON.stringify(uploadResult, null, 2)}</pre>
        </form>
      </section>

      <section className="grid">
        <article className="panel">
          <h2>What this frontend does</h2>
          <ul>
            <li>Shows the SafeGate landing page</li>
            <li>Checks the backend health endpoint</li>
            <li>Gives us a base for upload and report screens</li>
          </ul>
        </article>

        <article className="panel">
          <h2>Next UI milestones</h2>
          <ul>
            <li>Show upload metadata after submission</li>
            <li>File upload form</li>
            <li>Scan progress state</li>
            <li>Result / risk report page</li>
            <li>Temporary preview screen</li>
          </ul>
        </article>
      </section>
    </main>
  );
}
