"use client";

import { useEffect, useState } from "react";

export default function HomePage() {
  const [health, setHealth] = useState("checking");
  const [details, setDetails] = useState(null);

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

