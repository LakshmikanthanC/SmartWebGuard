import React, { useEffect, useRef, useState } from "react";
import { askAssistant, askAssistantStream } from "../../services/api";
import "./AiChatbot.css";

const STORAGE_KEY = "ai_chat_messages_v3";
const ENABLE_REMOTE_CHAT = import.meta.env.VITE_ENABLE_CHAT_API !== "false";
const FIRST_TOKEN_TIMEOUT_MS = Math.max(
  800,
  Number(import.meta.env.VITE_CHAT_FIRST_TOKEN_TIMEOUT_MS || 15000)
);
const FINAL_RESPONSE_TIMEOUT_MS = Math.max(
  2000,
  Number(import.meta.env.VITE_CHAT_FINAL_TIMEOUT_MS || 60000)
);
const WELCOME_MESSAGE = {
  id: "welcome",
  sender: "bot",
  text: "Hi! I can help with cybersecurity, coding, and general questions. Ask anything.",
};

const makeId = () =>
  (typeof crypto !== "undefined" && crypto.randomUUID)
    ? crypto.randomUUID()
    : `${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;

const formatErrorMessage = (error) => {
  const msg = String(error?.message || error || "").toLowerCase();
  
  if (msg.includes("provider_not_configured") || msg.includes("openai_api_key")) {
    return "Error: AI provider not configured. Please set OPENAI_API_KEY in the backend .env file.";
  }
  if (msg.includes("networkerror") || msg.includes("fetch") || msg.includes("econnrefused")) {
    return "Error: Cannot reach the AI service. The backend server may be down or the network is unavailable.";
  }
  if (msg.includes("timeout") || msg.includes("aborted")) {
    return "Error: Request timed out. The AI service took too long to respond. Please try again.";
  }
  if (msg.includes("401") || msg.includes("unauthorized")) {
    return "Error: Invalid API key. Please check your OPENAI_API_KEY in the backend configuration.";
  }
  if (msg.includes("429") || msg.includes("rate_limit")) {
    return "Error: Rate limit exceeded. Too many requests to the AI service. Please wait and try again.";
  }
  if (msg.includes("500") || msg.includes("internal")) {
    return "Error: AI service internal error. The provider is experiencing issues. Please try again later.";
  }
  if (msg.includes("503") || msg.includes("unavailable")) {
    return "Error: AI service temporarily unavailable. Please try again in a few moments.";
  }
  if (msg.includes("chat_stream_failed") || msg.includes("provider_stream_failed")) {
    const statusMatch = msg.match(/(\d{3})/);
    const status = statusMatch ? statusMatch[1] : "unknown";
    return `Error: AI stream failed (HTTP ${status}). Check backend logs for details.`;
  }
  if (msg.includes("chat_failed") || msg.includes("provider_request_failed")) {
    const statusMatch = msg.match(/(\d{3})/);
    const status = statusMatch ? statusMatch[1] : "unknown";
    return `Error: AI request failed (HTTP ${status}). Check backend logs for details.`;
  }
  
  return `Error: ${error?.message || error || "Unknown error occurred while contacting AI service."}`;
};

export default function AiChatbot({ inline = false }) {
  const [chatOpen, setChatOpen] = useState(false);
  const [chatInput, setChatInput] = useState("");
  const [isTyping, setIsTyping] = useState(false);
  const [chatMessages, setChatMessages] = useState([WELCOME_MESSAGE]);

  const chatBodyRef = useRef(null);
  const chatMessagesRef = useRef(chatMessages);
  const mountedRef = useRef(true);
  const streamAbortRef = useRef(null);

  useEffect(() => {
    chatMessagesRef.current = chatMessages;
  }, [chatMessages]);

  useEffect(() => {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (!stored) return;
      const parsed = JSON.parse(stored);
      if (Array.isArray(parsed) && parsed.length > 0) {
        setChatMessages(parsed);
      }
    } catch (err) {
      console.error("Failed to load chat history:", err);
    }
  }, []);

  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(chatMessages));
    } catch (err) {
      console.error("Failed to save chat history:", err);
    }
  }, [chatMessages]);

  useEffect(() => {
    if (chatBodyRef.current) {
      chatBodyRef.current.scrollTop = chatBodyRef.current.scrollHeight;
    }
  }, [chatMessages, chatOpen]);

  useEffect(() => {
    const handleEsc = (e) => {
      if (e.key === "Escape") setChatOpen(false);
    };
    window.addEventListener("keydown", handleEsc);
    return () => window.removeEventListener("keydown", handleEsc);
  }, []);

  useEffect(() => {
    if (chatOpen) setIsTyping(false);
  }, [chatOpen]);

  useEffect(() => {
    // Reset mountedRef on mount (important for React Strict Mode)
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      try {
        streamAbortRef.current?.abort();
      } catch {}
    };
  }, []);

  const handleChatSend = async (text) => {
    const msg = (text || chatInput || "").trim();
    if (!msg) return;
    console.log("[CHAT] Sending message:", msg);

    const userMsg = { id: makeId(), sender: "user", text: msg };
    const botMsgId = makeId();
    const nextHistory = [...chatMessagesRef.current, userMsg];

    // Show "Thinking..." immediately while waiting for real LLM response
    setChatMessages([
      ...nextHistory,
      { id: botMsgId, sender: "bot", text: "Thinking..." },
    ]);
    setChatInput("");
    setIsTyping(true);

    // Only use remote API - no local fallbacks
    let firstTokenTimer = null;
    let finalGuardTimer = null;
    try {
      if (!ENABLE_REMOTE_CHAT) {
        setChatMessages((prev) =>
          prev.map((m) =>
            m.id === botMsgId
              ? { ...m, text: "Error: Remote chat is disabled. Set VITE_ENABLE_CHAT_API=true to enable." }
              : m
          )
        );
        setIsTyping(false);
        return;
      }

      try {
        streamAbortRef.current?.abort();
      } catch {}
      const controller = new AbortController();
      streamAbortRef.current = controller;

      const historyForRemote = nextHistory
        .slice(-10)
        .map((m) => ({ role: m.sender, content: m.text }));
      let streamStarted = false;
      let streamedText = "";

      firstTokenTimer = setTimeout(() => {
        if (!mountedRef.current || streamStarted) return;
        setChatMessages((prev) =>
          prev.map((m) =>
            m.id === botMsgId
              ? { ...m, text: "Error: AI service is taking too long to respond. Please check if the backend is running and OPENAI_API_KEY is configured." }
              : m
          )
        );
        setIsTyping(false);
        controller.abort();
      }, FIRST_TOKEN_TIMEOUT_MS);

      finalGuardTimer = setTimeout(() => {
        if (!mountedRef.current) return;
        try {
          controller.abort();
        } catch {}
        if (!streamStarted) {
          setChatMessages((prev) =>
            prev.map((m) =>
              m.id === botMsgId
                ? { ...m, text: "Error: Request timed out. The AI service did not respond in time." }
                : m
            )
          );
        }
        setIsTyping(false);
      }, FINAL_RESPONSE_TIMEOUT_MS);

      console.log("[CHAT] Calling askAssistantStream...");
      const remoteReply = await askAssistantStream(msg, historyForRemote, {
        signal: controller.signal,
        onChunk: (_delta, fullText) => {
          console.log("[CHAT] Got chunk:", _delta);
          console.log("[CHAT] mountedRef.current:", mountedRef.current);
          console.log("[CHAT] botMsgId:", botMsgId);
          streamStarted = true;
          streamedText = fullText;
          if (!mountedRef.current) {
            console.log("[CHAT] Skipping - component unmounted!");
            return;
          }
          if (firstTokenTimer) {
            clearTimeout(firstTokenTimer);
            firstTokenTimer = null;
          }
          setIsTyping(false);
          console.log("[CHAT] Updating message with fullText:", fullText.substring(0, 50));
          setChatMessages((prev) => {
            console.log("[CHAT] prev messages count:", prev.length);
            const found = prev.find(m => m.id === botMsgId);
            console.log("[CHAT] Found message to update:", !!found);
            return prev.map((m) =>
              m.id === botMsgId ? { ...m, text: fullText } : m
            );
          });
        },
      });

      if (firstTokenTimer) {
        clearTimeout(firstTokenTimer);
        firstTokenTimer = null;
      }
      if (finalGuardTimer) {
        clearTimeout(finalGuardTimer);
        finalGuardTimer = null;
      }

      if (!mountedRef.current) return;
      if (remoteReply) {
        setChatMessages((prev) =>
          prev.map((m) =>
            m.id === botMsgId ? { ...m, text: remoteReply } : m
          )
        );
      } else if (!streamStarted) {
        setChatMessages((prev) =>
          prev.map((m) =>
            m.id === botMsgId
              ? { ...m, text: "Error: AI service returned an empty response. Please try again." }
              : m
          )
        );
      }
    } catch (err) {
      console.error("[CHAT] Stream failed:", err);
      // Try non-stream fallback first
      try {
        console.log("[CHAT] Trying non-stream fallback...");
        const { data } = await askAssistant(
          msg,
          nextHistory.slice(-10).map((m) => ({ role: m.sender, content: m.text }))
        );
        const remoteReply = (data?.reply || data?.message || data?.text || "").trim();
        if (!mountedRef.current) return;
        if (remoteReply && !remoteReply.toLowerCase().includes("local-fallback")) {
          setChatMessages((prev) =>
            prev.map((m) =>
              m.id === botMsgId ? { ...m, text: remoteReply } : m
            )
          );
        } else {
          // If it's a local fallback or empty, show error
          const errorMsg = formatErrorMessage(err);
          setChatMessages((prev) =>
            prev.map((m) =>
              m.id === botMsgId ? { ...m, text: errorMsg } : m
            )
          );
        }
      } catch (fallbackErr) {
        console.error("Chat failed:", fallbackErr || err);
        if (!mountedRef.current) return;
        const errorMsg = formatErrorMessage(fallbackErr || err);
        setChatMessages((prev) =>
          prev.map((m) =>
            m.id === botMsgId ? { ...m, text: errorMsg } : m
          )
        );
      }
    } finally {
      if (firstTokenTimer) {
        clearTimeout(firstTokenTimer);
        firstTokenTimer = null;
      }
      if (finalGuardTimer) {
        clearTimeout(finalGuardTimer);
        finalGuardTimer = null;
      }
      if (mountedRef.current) {
        setIsTyping(false);
      }
    }
  };

  const chatSuggestions = [
    "How to fix a React state bug?",
    "Explain phishing in simple words",
    "Write a Python API example",
    "How to debug a 500 error?",
    "Password security best practices",
    "What can you do?",
  ];

  const handleClearChat = () => {
    setChatMessages([WELCOME_MESSAGE]);
  };

  return (
    <div className={`ai-chat-root ${inline ? "ai-chat-root-inline" : ""}`}>
      <button
        className={`ai-chat-trigger ${inline ? "ai-chat-trigger-inline" : ""} ${
          chatOpen ? "ai-chat-trigger-open" : ""
        }`}
        onClick={() => setChatOpen((o) => !o)}
        aria-label="Toggle AI Assistant"
      >
        <span className="ai-chat-trigger-icon">{chatOpen ? "X" : "AI"}</span>
        <span className="ai-chat-trigger-label">
          {chatOpen ? "Close" : "AI Assistant"}
        </span>
      </button>

      <div
        className={`ai-chat-panel ${inline ? "ai-chat-panel-inline" : ""} ${
          chatOpen ? "ai-chat-panel-open" : ""
        }`}
      >
        <div className="ai-chat-header">
          <div className="ai-chat-header-left">
            <div className="ai-chat-avatar">AI</div>
            <div>
              <div className="ai-chat-title">AI Assistant</div>
              <div className="ai-chat-subtitle">
                <span className="ai-chat-dot" /> Online - Chat
              </div>
            </div>
          </div>
          <div className="ai-chat-header-actions">
            <button
              className="ai-chat-header-btn"
              onClick={handleClearChat}
              title="Clear chat"
            >
              C
            </button>
            <button
              className="ai-chat-header-btn ai-chat-close-btn"
              onClick={() => setChatOpen(false)}
              title="Close"
            >
              X
            </button>
          </div>
        </div>

        <div className="ai-chat-body" ref={chatBodyRef}>
          {chatMessages.map((msg) => (
            <div key={msg.id} className={`ai-chat-row ai-chat-row-${msg.sender}`}>
              {msg.sender === "bot" && <div className="ai-chat-row-avatar">AI</div>}
              <div className={`ai-chat-bubble ai-chat-bubble-${msg.sender}`}>
                {msg.text}
              </div>
            </div>
          ))}

          {isTyping && (
            <div className="ai-chat-row ai-chat-row-bot">
              <div className="ai-chat-row-avatar">AI</div>
              <div className="ai-chat-bubble ai-chat-bubble-bot ai-chat-typing">
                <span />
                <span />
                <span />
              </div>
            </div>
          )}
        </div>

        <div className="ai-chat-suggestions">
          {chatSuggestions.map((s) => (
            <button
              key={s}
              className="ai-chat-suggestion-btn"
              onClick={() => handleChatSend(s)}
            >
              {s}
            </button>
          ))}
        </div>

        <div className="ai-chat-input-row">
          <input
            className="ai-chat-input"
            type="text"
            placeholder="Ask security, coding, or general questions..."
            value={chatInput}
            onChange={(e) => setChatInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleChatSend()}
          />
          <button
            className="ai-chat-send-btn"
            onClick={() => handleChatSend()}
            disabled={!chatInput.trim()}
          >
            {"->"}
          </button>
        </div>
      </div>

      {chatOpen && (
        <div
          className={`ai-chat-backdrop ${inline ? "ai-chat-backdrop-inline" : ""}`}
          onClick={() => setChatOpen(false)}
        />
      )}
    </div>
  );
}
