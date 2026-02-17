import React from "react";
import { sevColor, sevBg, atkIcon, atkColor, fmtPct } from "../../utils/formatters";
import "./PredictionResult.css";

export default function PredictionResult({ result }) {
  if (!result) {
    return (
      <div className="card">
        <div className="empty">
          <div className="empty-icon">🤖</div>
          <p>Submit traffic features to see AI prediction results</p>
        </div>
      </div>
    );
  }

  return (
    <div className="card pr-card anim-up">
      <div className="card-hdr">
        <span className="card-title">📋 Prediction Result</span>
      </div>

      {/* Verdict Banner */}
      <div
        className="pr-verdict"
        style={{
          borderColor: result.is_malicious ? "var(--red)" : "var(--green)",
          background: result.is_malicious
            ? "rgba(255,71,87,0.06)"
            : "rgba(0,230,122,0.06)",
        }}
      >
        <div className="pr-verdict-icon">
          {result.is_malicious ? "🚨" : "✅"}
        </div>
        <div className="pr-verdict-body">
          <div
            className="pr-verdict-status"
            style={{
              color: result.is_malicious ? "var(--red)" : "var(--green)",
            }}
          >
            {result.is_malicious
              ? "MALICIOUS TRAFFIC DETECTED"
              : "NORMAL TRAFFIC"}
          </div>
          <div className="pr-verdict-type">
            {atkIcon(result.prediction)} {result.prediction?.toUpperCase()}
          </div>
        </div>
      </div>

      {/* Detail Grid */}
      <div className="pr-grid">
        <div className="pr-detail">
          <span className="pr-detail-label">Classification</span>
          <span
            className="pr-detail-val"
            style={{ color: atkColor(result.prediction) }}
          >
            {result.prediction?.toUpperCase()}
          </span>
        </div>
        <div className="pr-detail">
          <span className="pr-detail-label">Confidence</span>
          <span className="pr-detail-val">{fmtPct(result.confidence)}</span>
        </div>
        <div className="pr-detail">
          <span className="pr-detail-label">Severity</span>
          <span
            className="badge"
            style={{
              background: sevBg(result.severity),
              color: sevColor(result.severity),
              fontSize: "0.75rem",
            }}
          >
            {result.severity}
          </span>
        </div>
        <div className="pr-detail">
          <span className="pr-detail-label">Malicious</span>
          <span
            className="pr-detail-val"
            style={{
              color: result.is_malicious ? "var(--red)" : "var(--green)",
            }}
          >
            {result.is_malicious ? "YES" : "NO"}
          </span>
        </div>
      </div>

      {/* Probability Bars */}
      {result.probabilities && Object.keys(result.probabilities).length > 0 && (
        <div className="pr-probs">
          <h4 className="pr-probs-title">Classification Probabilities</h4>
          {Object.entries(result.probabilities)
            .sort(([, a], [, b]) => b - a)
            .map(([cls, prob]) => (
              <div key={cls} className="pr-prob-row">
                <span className="pr-prob-icon">{atkIcon(cls)}</span>
                <span className="pr-prob-name">{cls.toUpperCase()}</span>
                <div className="pr-prob-track">
                  <div
                    className="pr-prob-fill"
                    style={{
                      width: `${prob * 100}%`,
                      background: atkColor(cls),
                    }}
                  />
                </div>
                <span className="pr-prob-val">
                  {(prob * 100).toFixed(2)}%
                </span>
              </div>
            ))}
        </div>
      )}

      {/* Confidence Gauge */}
      <div className="pr-gauge-section">
        <h4 className="pr-probs-title">Confidence Gauge</h4>
        <div className="pr-gauge-wrap">
          <div className="pr-gauge-track">
            <div
              className="pr-gauge-fill"
              style={{
                width: `${result.confidence * 100}%`,
                background: result.is_malicious
                  ? "linear-gradient(90deg, var(--orange), var(--red))"
                  : "linear-gradient(90deg, var(--cyan), var(--green))",
              }}
            />
          </div>
          <div className="pr-gauge-labels">
            <span>0%</span>
            <span style={{ fontWeight: 700, color: "var(--text)" }}>
              {fmtPct(result.confidence)}
            </span>
            <span>100%</span>
          </div>
        </div>
      </div>
    </div>
  );
}