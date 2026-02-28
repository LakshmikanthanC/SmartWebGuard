import React, { useEffect, useRef, useState } from "react";
import { askAssistant, askAssistantStream } from "../../services/api";
import "./AiChatbot.css";

const STORAGE_KEY = "ai_chat_messages_v3";
const ENABLE_REMOTE_CHAT = import.meta.env.VITE_ENABLE_CHAT_API !== "false";
const FIRST_TOKEN_TIMEOUT_MS = Math.max(
  800,
  Number(import.meta.env.VITE_CHAT_FIRST_TOKEN_TIMEOUT_MS || 1800)
);
const FINAL_RESPONSE_TIMEOUT_MS = Math.max(
  2000,
  Number(import.meta.env.VITE_CHAT_FINAL_TIMEOUT_MS || 3000)
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

const toSqlType = (name) => {
  const n = name.toLowerCase();
  if (n.includes("id")) return "INT";
  if (n.includes("email")) return "VARCHAR(255)";
  if (n.includes("date") || n.includes("time")) return "TIMESTAMP";
  if (n.includes("count") || n.includes("qty") || n.includes("age")) return "INT";
  if (n.includes("price") || n.includes("amount") || n.includes("total")) return "DECIMAL(10,2)";
  return "VARCHAR(255)";
};

const buildSqlCreateTableReply = (input) => {
  const text = String(input || "");
  const lower = text.toLowerCase();
  const tableMatch = lower.match(/(?:create\s+table|table)\s+([a-z_][a-z0-9_]*)/i);
  const tableName = tableMatch?.[1] || "my_table";

  let cols = [];
  const withMatch = text.match(/\bwith\s+(.+)$/i);
  if (withMatch?.[1]) {
    cols = withMatch[1]
      .split(/,| and /i)
      .map((s) => s.trim().toLowerCase().replace(/[^a-z0-9_ ]/g, "").replace(/\s+/g, "_"))
      .filter(Boolean);
  }
  if (!cols.length) {
    cols = ["name", "email"];
  }

  const seen = new Set(["id"]);
  const fieldLines = cols
    .filter((c) => {
      if (!c || seen.has(c)) return false;
      seen.add(c);
      return true;
    })
    .map((c) => `  ${c} ${toSqlType(c)}${c === "email" ? " NOT NULL UNIQUE" : ""},`);

  return [
    "Use this SQL command:",
    `CREATE TABLE ${tableName} (`,
    "  id INT PRIMARY KEY AUTO_INCREMENT,",
    ...fieldLines,
    "  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP",
    ");",
  ].join("\n");
};

const extractTopicFromPrompt = (input) => {
  const text = String(input || "").trim();
  const patterns = [
    /(?:what is|what's)\s+(.+)\??$/i,
    /(?:explain|about|define)\s+(.+)$/i,
    /(?:topic|subject)\s*:\s*(.+)$/i,
  ];
  for (const rx of patterns) {
    const m = text.match(rx);
    if (m?.[1]) return m[1].trim().replace(/[?.!]+$/, "");
  }
  if (text.split(/\s+/).length <= 6) return text.replace(/[?.!]+$/, "");
  return "";
};

const buildTopicExplanation = (topic) => {
  const t = String(topic || "").trim();
  if (!t) return "";
  return [
    `${t} is a concept/topic that refers to its core idea and practical use in real-world systems.`,
    `In simple terms: ${t} helps solve a specific problem by giving a clear method or approach.`,
    "Why it matters:",
    "1. It improves understanding and decision-making.",
    "2. It is commonly used in implementation and troubleshooting.",
    "3. Learning it helps you build and debug faster.",
    "",
    `If you want, I can explain "${t}" with a beginner example or advanced version.`
  ].join("\n");
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
    return () => {
      mountedRef.current = false;
      try {
        streamAbortRef.current?.abort();
      } catch {}
    };
  }, []);

  const getLocalBotResponse = (input) => {
    const lower = input.toLowerCase();
    const asksCreateTable = /(create\s+table|sql\s+table|table\s+schema)/.test(lower);
    const extractedTopic = extractTopicFromPrompt(input);
    const debugRequest =
      /bug|error|debug|fix|not working|exception|stack trace|traceback|crash/.test(
        lower
      );
    const codingTopic =
      /code|coding|program|function|class|api|algorithm|python|node|javascript|typescript|java|c\+\+|sql/.test(
        lower
      );

    if (/^(hi|hello|hey|yo|sup)\b/.test(lower)) {
      return "Hello! Ask me about security, coding, or any general topic.";
    }

    if (/what can you do|help me|capabilities/.test(lower)) {
      return "I can help with:\n- Cybersecurity guidance\n- Coding help (React, JS, Python, debugging)\n- General Q&A and explanations\n\nFor best results, include context and your goal.";
    }

    if (/what is|explain|difference between|compare/.test(lower) && extractedTopic) {
      return buildTopicExplanation(extractedTopic);
    }

    if (/react|jsx|vite|hook|component|state|props|useeffect/.test(lower)) {
      return "For React issues, check:\n- component mount/unmount behavior\n- state dependencies in useEffect\n- stale closures in async handlers\n- key props for list rendering\n- cleanup of timers/listeners on unmount";
    }

    if (asksCreateTable) {
      return buildSqlCreateTableReply(input);
    }

    if (/python|node|javascript|typescript|java|c\+\+|sql/.test(lower)) {
      return "I can explain syntax, write examples, and debug logic for that stack. Ask with a concrete task like: 'write a Node API route', 'fix this Python traceback', or 'optimize this SQL query'.";
    }

    if (
      /phish|malware|ransomware|mfa|2fa|password|vpn|owasp|ddos|security|cyber/.test(
        lower
      )
    ) {
      return "Security quick checklist:\n- Verify links/domains before clicking\n- Use MFA and unique passwords\n- Keep OS/packages updated\n- Avoid unknown attachments/downloads\n- Use backups and least privilege";
    }

    if (/what is|explain|difference between|compare/.test(lower)) {
      return "Sure. I can explain it clearly. Tell me the exact topic and your level (beginner/intermediate/advanced), and I will tailor the answer.";
    }

    if (debugRequest) {
      const shortTopic = input.trim().slice(0, 80);
      return `I can help debug this: "${shortTopic}".\n\nPlease send:\n1. Language/framework\n2. Exact error message\n3. Expected vs actual behavior\n4. Minimal code snippet\n\nI will give a direct fix.`;
    }

    if (codingTopic) {
      return "I can help with coding tasks like API building, debugging, and optimization. Tell me what you want to build and your stack (e.g., React + Node, Python Flask, SQL).";
    }

    const topic = input.trim().slice(0, 80);
    return `I got your question: "${topic}". Share a bit more detail (goal, stack, error/output) and I will give a precise answer.`;
  };

  const handleChatSend = async (text) => {
    const msg = (text || chatInput || "").trim();
    if (!msg) return;

    const userMsg = { id: makeId(), sender: "user", text: msg };
    const nextHistory = [...chatMessagesRef.current, userMsg];

    const localReplyId = makeId();
    const localReply = getLocalBotResponse(msg);

    setChatMessages([
      ...nextHistory,
      { id: localReplyId, sender: "bot", text: localReply },
    ]);
    setChatInput("");
    setIsTyping(false);

    // Upgrade local answer with backend stream if available, without blocking UI.
    void (async () => {
      let firstTokenTimer = null;
      let finalGuardTimer = null;
      try {
        if (!ENABLE_REMOTE_CHAT) {
          setChatMessages((prev) =>
            prev.map((m) =>
              m.id === localReplyId ? { ...m, text: localReply } : m
            )
          );
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

        firstTokenTimer = setTimeout(() => {
          if (!mountedRef.current || streamStarted) return;
          setChatMessages((prev) =>
            prev.map((m) =>
              m.id === localReplyId ? { ...m, text: localReply } : m
            )
          );
          setIsTyping(false);
        }, FIRST_TOKEN_TIMEOUT_MS);
        finalGuardTimer = setTimeout(() => {
          if (!mountedRef.current) return;
          try {
            controller.abort();
          } catch {}
          setChatMessages((prev) =>
            prev.map((m) =>
              m.id === localReplyId && (!m.text || m.text.trim() === "Thinking...")
                ? { ...m, text: localReply }
                : m
            )
          );
          setIsTyping(false);
        }, FINAL_RESPONSE_TIMEOUT_MS);

        const remoteReply = await askAssistantStream(msg, historyForRemote, {
          signal: controller.signal,
          onChunk: (_delta, fullText) => {
            streamStarted = true;
            if (!mountedRef.current) return;
            if (firstTokenTimer) {
              clearTimeout(firstTokenTimer);
              firstTokenTimer = null;
            }
            setIsTyping(false);
            setChatMessages((prev) =>
              prev.map((m) =>
                m.id === localReplyId ? { ...m, text: fullText } : m
              )
            );
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
              m.id === localReplyId ? { ...m, text: remoteReply } : m
            )
          );
        } else if (!streamStarted) {
          setChatMessages((prev) =>
            prev.map((m) =>
              m.id === localReplyId ? { ...m, text: localReply } : m
            )
          );
        }
      } catch (err) {
        // Non-stream fallback for older backends.
        try {
          const { data } = await askAssistant(
            msg,
            nextHistory.slice(-10).map((m) => ({ role: m.sender, content: m.text }))
          );
          const remoteReply = (data?.reply || data?.message || data?.text || "").trim();
          if (!mountedRef.current) return;
          setChatMessages((prev) =>
            prev.map((m) =>
              m.id === localReplyId
                ? { ...m, text: remoteReply || localReply }
                : m
            )
          );
        } catch (fallbackErr) {
          console.error("Chat upgrade failed:", fallbackErr || err);
          if (!mountedRef.current) return;
          setChatMessages((prev) =>
            prev.map((m) =>
              m.id === localReplyId ? { ...m, text: localReply } : m
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
          setChatMessages((prev) =>
            prev.map((m) =>
              m.id === localReplyId && (!m.text || m.text.trim() === "Thinking...")
                ? { ...m, text: localReply }
                : m
            )
          );
          setIsTyping(false);
        }
      }
    })();
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
