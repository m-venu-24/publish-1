import { useEffect, useRef, useState } from "react";
import {
  ShieldCheck,
  Mail,
  Link2,
  MessageSquare,
  BookOpen,
  Search,
  Loader2,
  AlertTriangle,
  Info,
  Lock,
  Upload,
  Copy,
  Check,
  Eye,
  ListFilter,
  Sparkles,
} from "lucide-react";

const API = import.meta.env.VITE_API_URL || "";
const MAX = 20000;

const MODES = [
  { id: "email", label: "Email", Icon: Mail, hint: "Paste the full email including From: and Reply-To: headers, or upload an .EML file." },
  { id: "url", label: "URL", Icon: Link2, hint: "Paste one web address. It is parsed as text and never opened." },
  { id: "message", label: "Message", Icon: MessageSquare, hint: "Paste an SMS, WhatsApp, or chat message (supports English, Tanglish, and Tamil)." },
  { id: "journal", label: "Journal Website", Icon: BookOpen, hint: "Paste an academic journal website link, publication CFP, or paper-mill review offer." },
];

const SAMPLES = {
  email: [
    ["Fake bank alert", "From: HDFCBANK Alerts <alerts@hdfc-secure.example>\nReply-To: help@other.example\nSubject: Account notice\n\nURGENT! Your account has been suspended. Verify your account and share your OTP within 24 hours: http://hdfc-secure.example/login"],
    ["SBI PAN KYC fraud", "From: State Bank Notice <support@sbi-updates.net>\nReply-To: verify@quick-kyc.org\nSubject: YONO Mandatory KYC Verification\n\nDear SBI customer, your netbanking will be blocked tonight. Update your PAN card and Aadhaar immediately to avoid ₹10,000 fine: http://sbi-kyc-update.xyz"],
    ["Predatory journal CFP", "From: Editorial Board <editor@global-rapid-journal.org>\nReply-To: submissions@other-mail.example\nSubject: Call for Papers - Rapid Publication Guaranteed\n\nDear Esteemed Professor, We reviewed your work and invite you to publish in the International Journal of Advanced Research. We guarantee peer review and acceptance within 48 hours! Impact Factor: 7.94 (Global Impact Factor). Pay APC processing fee now to secure your publication seat: http://scopus-indexed-journal.org/pay-apc"],
    ["Normal meeting email", "From: Priya <priya@college.example>\nSubject: Lab schedule\n\nHi, the lab session is moved to Thursday 2 PM. Please bring your record book."],
  ],
  message: [
    ["Tanglish EB Power Cut", "TNEB EB Alert: Ungal veetu electricity line inre 10 PM cut aagidum previous month bill pay pannalana. Udane EB Officer Mohan 9444123456 call panni bill clear pannunga."],
    ["Tamil Bank KYC Fraud", "வங்கி கணக்கு முடக்கப்படும்! உங்கள் எஸ்பிஐ வங்கி கேஒய்சி முடிவடைந்தது. உடனே பான் கார்டு இணைக்கவும்: http://sbi-kyc-update.xyz"],
    ["UPI Scratch Card Scam", "Google Pay Cashback: Congratulations! You have won ₹1999 scratch card reward! Enter your UPI PIN to claim money directly to bank account: bit.ly/gpay-reward"],
    ["India Post Parcel Hold", "India Post: Your package #IN7821389 cannot be delivered due to incomplete home address. Update address within 12 hours to avoid return: http://indiapost-parcel-delivery.com"],
    ["Job / WFH Telegram Scam", "Earn ₹2000 to ₹5000 daily working from home liking YouTube videos! Pay ₹500 refundable security fee to activate your seat."],
    ["Normal message", "Project meeting is tomorrow at 10 AM in the seminar hall. Please bring the slide deck."],
  ],
  url: [
    ["Cloned journal site", "https://nature-openaccess-journal.org/submit-manuscript"],
    ["Lookalike brand domain", "https://paypa1.com/signin"],
    ["@ credential trick", "https://paypal.com@login-check.example/verify"],
    ["Legitimate site", "https://github.com/anthropics"],
  ],
  journal: [
    ["Cloned journal site", "https://nature-openaccess-journal.org/submit-manuscript"],
    ["Hijacked Scopus link", "https://scopus-indexed-journal.org/pay-apc"],
    ["Bogus impact claim", "https://elsevier-fastpublication.org/peer-review-guarantee\n\nGuaranteed acceptance in 24 hours! Universal Impact Factor: 8.92. Pay APC processing fee via Western Union."],
    ["Official journal (safe)", "https://www.nature.com/nature/for-authors/initial-submission"],
  ],
};

const LEVEL_TEXT = { low: "Low", medium: "Medium", high: "High", critical: "Critical" };
const VERDICT_TEXT = {
  no_known_warning_signs: "No known warning signs",
  minor_signals: "Minor signals",
  needs_review: "Needs review",
  suspicious: "Suspicious",
};

function friendlyError(status, body) {
  if (status === 429) {
    return "Rate limit reached (60 scans per minute). Please wait a few moments before trying again.";
  }
  if (status === 422) {
    const d = body?.detail;
    const msg = Array.isArray(d) ? d.map((x) => x.msg || x).join(" ") : d;
    return msg ? `The input was rejected: ${msg}` : "The input was rejected. Check that it is not empty and is under 20,000 characters.";
  }
  if (status >= 500) return "The scanner hit an internal error. Try again, or shorten the input.";
  return `Unexpected response from the server (${status}).`;
}

function ScoreGauge({ score, level }) {
  const radius = 65;
  const stroke = 12;
  const normalizedRadius = radius - stroke;
  const circumference = Math.PI * normalizedRadius;
  const strokeDashoffset = circumference - (Math.min(100, Math.max(0, score)) / 100) * circumference;

  const colorMap = {
    low: "#1f7a4d",
    medium: "#d19a1c",
    high: "#b4430f",
    critical: "#a3122a",
  };
  const color = colorMap[level] || "#1f7a4d";

  return (
    <div className="gauge-container" aria-label={`Score ${score} out of 100`}>
      <svg height="95" width="160" viewBox="0 0 160 95" className="gauge-svg">
        <path
          d="M 15 85 A 65 65 0 0 1 145 85"
          fill="none"
          stroke="#e2e8f0"
          strokeWidth="12"
          strokeLinecap="round"
        />
        <path
          d="M 15 85 A 65 65 0 0 1 145 85"
          fill="none"
          stroke={color}
          strokeWidth="12"
          strokeLinecap="round"
          strokeDasharray={`${circumference} ${circumference}`}
          style={{ strokeDashoffset, transition: "stroke-dashoffset 0.8s ease-in-out" }}
        />
      </svg>
      <div className="gauge-text">
        <span className="gauge-score" style={{ color }}>{score}</span>
        <span className="gauge-denom">/100</span>
      </div>
    </div>
  );
}

function HighlightedText({ text, findings, mlTerms }) {
  if (!text) return null;

  const phraseSet = new Set();
  findings.forEach((f) => {
    if (f.evidence) {
      f.evidence.split(";").forEach((p) => {
        const clean = p.trim().replace(/^['"]+|['"]+$/g, "");
        if (clean.length > 2 && !clean.includes("looks like") && !clean.includes("(+")) {
          phraseSet.add(clean.toLowerCase());
        }
      });
    }
    if (f.url) phraseSet.add(f.url.toLowerCase());
  });

  if (mlTerms) {
    mlTerms.forEach((t) => {
      if (t.term && t.term.length > 2) phraseSet.add(t.term.toLowerCase());
    });
  }

  const phrases = Array.from(phraseSet).sort((a, b) => b.length - a.length);

  let parts = [{ text, isMatch: false }];

  phrases.forEach((phrase) => {
    const nextParts = [];
    parts.forEach((part) => {
      if (part.isMatch) {
        nextParts.push(part);
        return;
      }
      const idx = part.text.toLowerCase().indexOf(phrase);
      if (idx !== -1) {
        const before = part.text.slice(0, idx);
        const match = part.text.slice(idx, idx + phrase.length);
        const after = part.text.slice(idx + phrase.length);
        if (before) nextParts.push({ text: before, isMatch: false });
        nextParts.push({ text: match, isMatch: true });
        if (after) nextParts.push({ text: after, isMatch: false });
      } else {
        nextParts.push(part);
      }
    });
    parts = nextParts;
  });

  return (
    <div className="highlight-container">
      {parts.map((p, i) =>
        p.isMatch ? (
          <mark key={i} className="highlighted-evidence">{p.text}</mark>
        ) : (
          <span key={i}>{p.text}</span>
        )
      )}
    </div>
  );
}

export default function App() {
  const [mode, setMode] = useState("message");
  const [text, setText] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState(null);
  const [online, setOnline] = useState(null);
  const [elapsed, setElapsed] = useState(null);
  const [toastMessage, setToastMessage] = useState("");
  const resultRef = useRef(null);
  const fileInputRef = useRef(null);

  useEffect(() => {
    fetch(`${API}/api/health`).then((r) => setOnline(r.ok)).catch(() => setOnline(false));
  }, []);

  useEffect(() => {
    if (result) resultRef.current?.focus();
  }, [result]);

  const current = MODES.find((m) => m.id === mode);

  function triggerToast(msg) {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(""), 2800);
  }

  function handleFileUpload(e) {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result;
      if (typeof content === "string") {
        setText(content);
        setMode("email");
        setError("");
        setResult(null);
        triggerToast(`Loaded file: ${file.name}`);
      }
    };
    reader.readAsText(file);
    e.target.value = "";
  }

  async function analyze() {
    if (!text.trim()) return setError("Paste something to analyze first.");
    setError("");
    setLoading(true);
    setResult(null);
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 15000);
    const t0 = performance.now();
    try {
      const res = await fetch(`${API}/api/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ content_type: mode, content: text }),
        signal: ctrl.signal,
      });
      const body = await res.json().catch(() => null);
      if (!res.ok) throw new Error(friendlyError(res.status, body));
      setResult(body);
      setElapsed(Math.round(performance.now() - t0));
      setOnline(true);
    } catch (e) {
      if (e.name === "AbortError") setError("The scan took longer than 15 seconds and was cancelled.");
      else if (e instanceof TypeError) {
        setOnline(false);
        setError(`Cannot reach the scanner at ${API || "server"}. Verify the server is running.`);
      } else setError(e.message);
    } finally {
      clearTimeout(timer);
      setLoading(false);
    }
  }

  function onKey(e) {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") analyze();
  }

  return (
    <div className="page">
      <header className="top">
        <div className="brand">
          <ShieldCheck size={28} aria-hidden="true" />
          <div>
            <h1>PhishGuard AI</h1>
            <p>Hybrid explainable phishing triage with regional Tanglish/Tamil and academic journal threat detection</p>
          </div>
        </div>
        <span className={`status ${online === null ? "" : online ? "up" : "down"}`} role="status">
          <i aria-hidden="true" />
          {online === null ? "Checking scanner" : online ? "Scanner online" : "Scanner offline"}
        </span>
      </header>

      <main className="grid">
        <section className="panel" aria-labelledby="in-h">
          <h2 id="in-h">What do you want to check?</h2>
          <div className="tabs" role="tablist" aria-label="Input type">
            {MODES.map(({ id, label, Icon }) => (
              <button
                key={id}
                role="tab"
                aria-selected={mode === id}
                className={mode === id ? "tab on" : "tab"}
                onClick={() => {
                  setMode(id);
                  setError("");
                }}
              >
                <Icon size={16} aria-hidden="true" /> {label}
              </button>
            ))}
          </div>

          <div className="input-toolbar">
            <p className="hint">{current.hint}</p>
            {mode === "email" && (
              <>
                <input
                  type="file"
                  accept=".eml,.txt"
                  ref={fileInputRef}
                  style={{ display: "none" }}
                  onChange={handleFileUpload}
                />
                <button
                  type="button"
                  className="upload-btn"
                  onClick={() => fileInputRef.current?.click()}
                  title="Upload .EML or text file"
                >
                  <Upload size={14} /> Upload .EML file
                </button>
              </>
            )}
          </div>

          <label htmlFor="input" className="sr">Content to analyze</label>
          <textarea
            id="input"
            value={text}
            maxLength={MAX}
            onChange={(e) => setText(e.target.value)}
            onKeyDown={onKey}
            placeholder={
              mode === "url" || mode === "journal"
                ? "https://… or paste website text"
                : mode === "email"
                ? "From: support@example.com\nSubject: ...\n\nPaste message here..."
                : "Paste SMS, WhatsApp, Tanglish, or Tamil message here…"
            }
            rows={mode === "url" ? 3 : mode === "journal" ? 5 : 9}
          />
          <div className="row">
            <span className="count">{text.length.toLocaleString()} / {MAX.toLocaleString()}</span>
            <div className="samples">
              <span>Try a sample:</span>
              {SAMPLES[mode].map(([name, val]) => (
                <button
                  key={name}
                  className="chip"
                  onClick={() => {
                    setText(val);
                    setResult(null);
                    setError("");
                  }}
                >
                  {name}
                </button>
              ))}
            </div>
          </div>

          <p className="privacy">
            <Lock size={15} aria-hidden="true" />
            <span>
              <strong>Privacy guarantee:</strong> No external calls at inference. Evaluated purely in-memory by local hybrid heuristics and statistical model. Links are never visited.
            </span>
          </p>

          <button className="go" onClick={analyze} disabled={loading}>
            {loading ? (
              <>
                <Loader2 size={18} className="spin" aria-hidden="true" /> Analyzing…
              </>
            ) : (
              <>
                <Search size={18} aria-hidden="true" /> Analyze Content
              </>
            )}
          </button>
          {error && (
            <div className="error" role="alert">
              <AlertTriangle size={18} aria-hidden="true" /> <span>{error}</span>
            </div>
          )}
        </section>

        <section className="panel results" aria-live="polite" aria-labelledby="out-h">
          <h2 id="out-h">Triage Report</h2>
          {!result && !loading && (
            <p className="empty">Paste text or a URL on the left and choose Analyze. Each warning will show calibrated evidence and explainability scores.</p>
          )}
          {loading && <p className="empty">Scanning with hybrid rule engine & ML classifier…</p>}
          {result && (
            <Result
              r={result}
              ms={elapsed}
              refEl={resultRef}
              originalText={text}
              mode={mode}
              onToast={triggerToast}
            />
          )}
        </section>
      </main>

      {toastMessage && (
        <div className="toast" role="status">
          <Check size={16} /> <span>{toastMessage}</span>
        </div>
      )}

      <footer>
        PhishGuard AI Hybrid v0.3 • 40% Explainable Heuristics + 60% Statistical Classifier • Local In-Memory Evaluation
      </footer>
    </div>
  );
}

function Result({ r, ms, refEl, originalText, mode, onToast }) {
  const [feedbackStatus, setFeedbackStatus] = useState("");
  const [activeTab, setActiveTab] = useState("findings"); // "findings" | "highlight"
  const [copied, setCopied] = useState(false);

  function copyFormattedReport() {
    const report = [
      `# PhishGuard AI - Triage Assessment Report`,
      `Generated: ${new Date().toISOString()}`,
      `Verdict: ${VERDICT_TEXT[r.verdict] || r.verdict} (${LEVEL_TEXT[r.risk_level]} Risk)`,
      `Score: ${r.risk_score} / 100`,
      `Engine: ${r.engine}`,
      `Composition: Rule component (${r.rule_score || 0}/100) + ML Classifier (${Math.round((r.ml_probability || 0) * 100)}%)`,
      `Detected Language: ${r.breakdown?.detected_language || "English"}`,
      ``,
      `## Recommended Action`,
      `${r.recommended_action}`,
      ``,
      `## Findings (${r.findings.length})`,
      ...r.findings.map(
        (f, i) =>
          `${i + 1}. [${f.severity.toUpperCase()}] ${f.type.replace(/_/g, " ")}: ${f.reason}${f.evidence ? ` (Evidence: "${f.evidence}")` : ""}${f.url ? ` (Link: ${f.url})` : ""}`
      ),
      ``,
      `## Technical Signals`,
      `- URL Risk Flags: ${r.breakdown?.url_signals || 0}`,
      `- Header Mismatch Flags: ${r.breakdown?.header_signals || 0}`,
      `- Top ML Predictive Tokens: ${(r.ml_terms || []).map((t) => `${t.term} (+${t.weight.toFixed(2)})`).join(", ") || "None"}`,
      ``,
      `Privacy Note: No external calls at inference. Evaluated purely in-memory.`,
    ].join("\n");

    navigator.clipboard.writeText(report).then(() => {
      setCopied(true);
      onToast("Report copied to clipboard!");
      setTimeout(() => setCopied(false), 2500);
    });
  }

  async function sendFeedback(userLabel) {
    if (feedbackStatus) return;
    try {
      setFeedbackStatus("sending");
      await fetch(`${API}/api/feedback`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          content: originalText,
          content_type: mode,
          predicted_label: ["high", "critical"].includes(r.risk_level) ? "phishing" : "legitimate",
          user_label: userLabel,
          findings: r.findings,
          risk_level: r.risk_level,
        }),
      });
      setFeedbackStatus("sent");
      onToast("Thank you for your feedback!");
    } catch {
      setFeedbackStatus("error");
    }
  }

  return (
    <div className="res" tabIndex={-1} ref={refEl}>
      {/* Gauge & Verdict Banner */}
      <div className={`res-header lvl-${r.risk_level}`}>
        <div className="res-title">
          <div className="lvl-title">{LEVEL_TEXT[r.risk_level]} Risk</div>
          <div className="verdict-sub">{VERDICT_TEXT[r.verdict]}</div>
          <span className="hybrid-formula-badge">{r.risk_score_note}</span>
        </div>
        <div className="gauge-wrap">
          <ScoreGauge score={r.risk_score} level={r.risk_level} />
        </div>
      </div>

      {/* Toolbar: View Toggle & Share */}
      <div className="result-toolbar">
        <div className="view-tabs" role="tablist">
          <button
            type="button"
            className={`view-tab ${activeTab === "findings" ? "active" : ""}`}
            onClick={() => setActiveTab("findings")}
          >
            <ListFilter size={14} style={{ display: "inline", marginRight: 4 }} />
            Findings ({r.findings.length})
          </button>
          <button
            type="button"
            className={`view-tab ${activeTab === "highlight" ? "active" : ""}`}
            onClick={() => setActiveTab("highlight")}
          >
            <Eye size={14} style={{ display: "inline", marginRight: 4 }} />
            Evidence in Text
          </button>
        </div>

        <div className="action-btns">
          <button type="button" className="btn-action" onClick={copyFormattedReport} title="Copy markdown summary">
            {copied ? <Check size={14} /> : <Copy size={14} />} {copied ? "Copied" : "Copy Report"}
          </button>
        </div>
      </div>

      {/* "Why this verdict?" Explainability Breakdown Panel */}
      <div className="why-panel">
        <h4><Sparkles size={16} color="#4338ca" /> Explainability Breakdown</h4>
        <div className="why-grid">
          <div className="why-stat">
            <span>Rule Heuristic</span>
            <b>{r.rule_score} / 100</b>
          </div>
          <div className="why-stat">
            <span>ML Probability</span>
            <b>{Math.round((r.ml_probability || 0) * 100)}%</b>
          </div>
          <div className="why-stat">
            <span>URL Signals</span>
            <b>{r.breakdown?.url_signals || 0} found</b>
          </div>
          <div className="why-stat">
            <span>Language</span>
            <b>{r.breakdown?.detected_language || "English"}</b>
          </div>
        </div>

        {r.ml_terms && r.ml_terms.length > 0 && (
          <div className="why-terms">
            <div className="why-terms-label">Top Predictive Terms (TF-IDF Coefficients):</div>
            <div className="term-chips">
              {r.ml_terms.map((t, idx) => (
                <span key={idx} className="term-chip">
                  {t.term} (+{t.weight.toFixed(2)})
                </span>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Action recommendation */}
      <h3>Recommended Action</h3>
      <p>{r.recommended_action}</p>

      {/* View Content: Findings List OR Highlighted Text */}
      {activeTab === "findings" ? (
        <>
          <h3>Detailed Findings ({r.findings.length})</h3>
          {r.findings.length === 0 && (
            <p className="empty">No heuristic rule matched. That does not guarantee content is safe.</p>
          )}
          <ul className="findings">
            {r.findings.map((f, i) => {
              const isML = f.type === "ml_classifier" || f.type.startsWith("ml_");
              const isRegional = f.type.includes("tanglish") || f.type.includes("india_") || f.type.includes("tamil");
              return (
                <li key={i} className={`sev-${f.severity}`}>
                  <div className="fh">
                    <span className="pill">{f.severity}</span>
                    {isML && <span className="ml-badge">Statistical ML</span>}
                    {isRegional && <span className="regional-badge">India / Tanglish Rule</span>}
                    <code className="ftype">{f.type.replace(/_/g, " ")}</code>
                  </div>
                  <p>{f.reason}</p>
                  {f.evidence && (
                    <p className="ev">
                      <span>Evidence</span> <code>{f.evidence}</code>
                    </p>
                  )}
                  {f.url && (
                    <p className="ev">
                      <span>Link</span> <code>{f.url}</code>
                    </p>
                  )}
                </li>
              );
            })}
          </ul>
        </>
      ) : (
        <>
          <h3>Evidence Highlighted in Original Text</h3>
          <HighlightedText text={originalText} findings={r.findings} mlTerms={r.ml_terms} />
        </>
      )}

      {r.urls_found.length > 0 && (
        <>
          <h3>Parsed URLs ({r.urls_found.length})</h3>
          <ul className="urls">
            {r.urls_found.map((u) => (
              <li key={u}>
                <code>{u}</code>
              </li>
            ))}
          </ul>
        </>
      )}

      <h3>Limitations</h3>
      <ul className="lims">
        {r.limitations.map((l) => (
          <li key={l}>{l}</li>
        ))}
      </ul>

      {/* Accuracy Feedback */}
      <div
        className="feedback-section"
        style={{
          marginTop: "2rem",
          padding: "1rem",
          background: "var(--bg-panel-alt, #f9fafb)",
          borderRadius: "8px",
          border: "1px solid var(--line)",
        }}
      >
        <h4 style={{ marginTop: 0, fontSize: "0.95rem" }}>Was this triage verdict accurate?</h4>
        {feedbackStatus === "" ? (
          <div style={{ display: "flex", gap: "0.5rem", marginTop: "0.5rem" }}>
            <button
              onClick={() => sendFeedback(["high", "critical"].includes(r.risk_level) ? "phishing" : "legitimate")}
              className="chip"
              style={{ background: "#dcfce7", color: "#166534", border: "1px solid #bbf7d0" }}
            >
              Yes, accurate
            </button>
            <button
              onClick={() => sendFeedback(["high", "critical"].includes(r.risk_level) ? "legitimate" : "phishing")}
              className="chip"
              style={{ background: "#fee2e2", color: "#991b1b", border: "1px solid #fecaca" }}
            >
              No, wrong verdict
            </button>
          </div>
        ) : (
          <p style={{ marginTop: "0.5rem", color: feedbackStatus === "error" ? "red" : "green", fontSize: "0.88rem" }}>
            {feedbackStatus === "sending"
              ? "Recording feedback..."
              : feedbackStatus === "sent"
              ? "Thank you for helping improve the model!"
              : "Error recording feedback."}
          </p>
        )}
      </div>

      <p className="meta">
        Engine {r.engine}. Local processing {r.processing_ms} ms. Round trip {ms} ms.
      </p>
    </div>
  );
}
