"use client";

import { useEffect, useState } from "react";
import GeminiAssistant from "./GeminiAssistant";

export default function HomePage() {
  const [health, setHealth] = useState("checking");
  const [details, setDetails] = useState(null);
  const [urlInput, setUrlInput] = useState("");
  const [urlState, setUrlState] = useState("idle");
  const [urlResult, setUrlResult] = useState(null);
  const [analysisHistory, setAnalysisHistory] = useState([]);
  const [urlPreviewState, setUrlPreviewState] = useState("idle");
  const [urlPreviewResult, setUrlPreviewResult] = useState(null);
  const [selectedFile, setSelectedFile] = useState(null);
  const [uploadState, setUploadState] = useState("idle");
  const [uploadResult, setUploadResult] = useState(null);
  const [uploadPreviewState, setUploadPreviewState] = useState("idle");
  const [uploadPreviewResult, setUploadPreviewResult] = useState(null);

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

  async function runUrlAnalysis(targetUrl) {
    const normalizedUrl = targetUrl.trim();

    if (!normalizedUrl) {
      setUrlState("missing-url");
      setUrlResult({ error: "Please paste a download link first." });
      return;
    }

    setUrlInput(normalizedUrl);
    setUrlState("analyzing");
    setUrlResult(null);
    setUrlPreviewState("idle");
    setUrlPreviewResult(null);

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
        return;
      }

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
    } catch (error) {
      setUrlState("error");
      setUrlResult({ error: "URL analysis failed." });
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
      return;
    }

    setUploadState("uploading");
    setUploadResult(null);
    setUploadPreviewState("idle");
    setUploadPreviewResult(null);

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

  function renderPreviewPanel(preview, previewState) {
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
          {urlResult?.upload_id ? (
            <button
              type="button"
              onClick={() => loadPreview(urlResult.upload_id, setUrlPreviewState, setUrlPreviewResult)}
            >
              Load Safe Preview
            </button>
          ) : null}
          <pre>{JSON.stringify(urlResult, null, 2)}</pre>
          {urlResult?.source_state ? (
            <div className="fingerprintSummary">
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
                <p>This link looks like a webpage. SafeGate found candidate download links below.</p>
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
              {urlResult.candidate_urls?.length ? (
                <div className="candidateList">
                  <p>Candidate links:</p>
                  <ul>
                    {urlResult.candidate_urls.map((candidate) => (
                      <li key={candidate}>
                        <span>{candidate}</span>{" "}
                        <button type="button" onClick={() => handleCandidateInspect(candidate)}>
                          Inspect
                        </button>{" "}
                        <a href={candidate} target="_blank" rel="noreferrer">
                          Open
                        </a>
                      </li>
                    ))}
                  </ul>
                </div>
              ) : null}
            </div>
          ) : null}
          {urlResult?.candidate_details?.length ? (
            <div className="fingerprintSummary">
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
                        <button type="button" onClick={() => handleCandidateInspect(candidate.url)}>
                          Inspect
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
          {urlResult?.upload_id ? (
            <GeminiAssistant
              title="Gemini explanation and chat"
              analysis={{ ...urlResult, preview: urlPreviewResult }}
              analysisKey={urlResult.upload_id}
            />
          ) : null}
          {urlPreviewResult || urlPreviewState !== "idle" ? (
            <div className="fingerprintSummary">
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
              {renderPreviewPanel(urlPreviewResult, urlPreviewState)}
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
          {uploadResult?.upload_id ? (
            <button
              type="button"
              onClick={() => loadPreview(uploadResult.upload_id, setUploadPreviewState, setUploadPreviewResult)}
            >
              Load Safe Preview
            </button>
          ) : null}
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
          {uploadResult?.upload_id ? (
            <GeminiAssistant
              title="Gemini explanation and chat"
              analysis={{ ...uploadResult, preview: uploadPreviewResult }}
              analysisKey={uploadResult.upload_id}
            />
          ) : null}
          {uploadPreviewResult || uploadPreviewState !== "idle" ? (
            <div className="fingerprintSummary">
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
              {renderPreviewPanel(uploadPreviewResult, uploadPreviewState)}
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
