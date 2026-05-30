"use client";

import { useEffect, useState } from "react";

export default function GeminiAssistant({ analysis, analysisKey, title }) {
  const [explainState, setExplainState] = useState("idle");
  const [explanation, setExplanation] = useState(null);
  const [chatState, setChatState] = useState("idle");
  const [chatInput, setChatInput] = useState("");
  const [chatMessages, setChatMessages] = useState([]);

  useEffect(() => {
    setExplainState("idle");
    setExplanation(null);
    setChatState("idle");
    setChatInput("");
    setChatMessages([]);
  }, [analysisKey]);

  async function requestExplain() {
    if (!analysis) {
      setExplainState("missing-analysis");
      setExplanation({ error: "No analysis data is available yet." });
      return;
    }

    setExplainState("loading");
    setExplanation(null);

    try {
      const response = await fetch("/api/ai/explain", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ analysis }),
      });

      const data = await response.json();

      if (!response.ok) {
        setExplainState("error");
        setExplanation(data);
        return;
      }

      setExplainState("done");
      setExplanation(data);
    } catch (error) {
      setExplainState("error");
      setExplanation({ error: "Gemini explanation failed." });
    }
  }

  async function handleChatSubmit(event) {
    event.preventDefault();

    if (!analysis) {
      setChatState("missing-analysis");
      return;
    }

    const question = chatInput.trim();
    if (!question) {
      setChatState("missing-question");
      return;
    }

    const nextUserMessage = { role: "user", content: question };
    const nextHistory = [...chatMessages, nextUserMessage];

    setChatState("loading");
    setChatMessages(nextHistory);
    setChatInput("");

    try {
      const response = await fetch("/api/ai/chat", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          analysis,
          question,
          history: nextHistory,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        setChatState("error");
        setChatMessages((previous) => [...previous, { role: "assistant", content: data.error ?? "Chat failed." }]);
        return;
      }

      setChatState("done");
      setChatMessages((previous) => [...previous, { role: "assistant", content: data.answer }]);
    } catch (error) {
      setChatState("error");
      setChatMessages((previous) => [...previous, { role: "assistant", content: "Gemini chat failed." }]);
    }
  }

  return (
    <div className="fingerprintSummary">
      <h3>{title}</h3>
      <p>Gemini explains the technical data in plain English, in at most 2 lines.</p>
      <div className="geminiActions">
        <button type="button" onClick={requestExplain}>
          Explain with Gemini
        </button>
        <span className="geminiState">State: {explainState}</span>
      </div>
      {explanation?.answer ? (
        <p className="geminiAnswer">{explanation.answer}</p>
      ) : explanation?.error ? (
        <p className="geminiError">{explanation.error}</p>
      ) : null}

      <div className="geminiChat">
        <h4>Ask a related doubt</h4>
        <p>Ask follow-up questions about the current analysis. Answers stay short and focused.</p>
        <form onSubmit={handleChatSubmit} className="geminiChatForm">
          <input
            type="text"
            value={chatInput}
            onChange={(event) => setChatInput(event.target.value)}
            placeholder="Why is this file suspicious?"
          />
          <button type="submit">Ask Gemini</button>
        </form>
        <p className="geminiState">Chat state: {chatState}</p>
        {chatMessages.length ? (
          <div className="geminiChatMessages">
            {chatMessages.map((message, index) => (
              <div className={`geminiMessage ${message.role}`} key={`${message.role}-${index}`}>
                <strong>{message.role === "user" ? "You" : "Gemini"}:</strong> {message.content}
              </div>
            ))}
          </div>
        ) : null}
      </div>
    </div>
  );
}
