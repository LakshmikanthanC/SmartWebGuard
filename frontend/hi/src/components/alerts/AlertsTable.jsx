import React, { useState, useEffect, useCallback } from "react";
import { getAlerts, ackAlert, deleteAlert } from "../../services/api";
import { fmtDate, fmtPct, sevColor, sevBg, atkIcon } from "../../utils/formatters";
import AlertDetail from "./AlertDetail";
import "./AlertsTable.css";

export default function AlertsTable() {
  const [alerts, setAlerts] = useState([]);
  const [pg, setPg] = useState({});
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [filters, setFilters] = useState({ severity: "", attackType: "" });
  const [selected, setSelected] = useState(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const p = { page, limit: 15, ...filters };
      Object.keys(p).forEach((k) => !p[k] && delete p[k]);
      const { data } = await getAlerts(p);
      setAlerts(data.alerts);
      setPg(data.pagination);
    } catch {}
    setLoading(false);
  }, [page, filters]);

  useEffect(() => { load(); }, [load]);

  const handleAck = async (id) => {
    try { await ackAlert(id); setAlerts((a) => a.map((x) => (x._id === id ? { ...x, acknowledged: true } : x))); } catch {}
  };

  const handleDel = async (id) => {
    try { await deleteAlert(id); setAlerts((a) => a.filter((x) => x._id !== id)); } catch {}
  };

  return (
    <>
      {selected && <AlertDetail alert={selected} onClose={() => setSelected(null)} onAck={handleAck} />}

      <div className="card alerts-card">
        <div className="card-header">
          <span className="card-title"><span className="icon">🚨</span>Intrusion Alerts</span>
          <div className="card-actions">
            <select className="select" value={filters.severity} onChange={(e) => { setFilters((f) => ({ ...f, severity: e.target.value })); setPage(1); }}>
              <option value="">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
            <select className="select" value={filters.attackType} onChange={(e) => { setFilters((f) => ({ ...f, attackType: e.target.value })); setPage(1); }}>
              <option value="">All Types</option>
              <option value="dos">DoS</option>
              <option value="probe">Probe</option>
              <option value="r2l">R2L</option>
              <option value="u2r">U2R</option>
            </select>
            <button className="btn btn-ghost btn-sm" onClick={load}>↻ Refresh</button>
          </div>
        </div>

        {loading ? <div className="empty-state"><p>Loading alerts...</p></div> : !alerts.length ? (
          <div className="empty-state"><div className="empty-icon">🔍</div><p>No alerts match your filters</p></div>
        ) : (
          <div className="table-wrap">
            <table className="at-table">
              <thead>
                <tr>
                  <th>Time</th><th>Attack</th><th>Severity</th><th>Source</th><th>Destination</th>
                  <th>Protocol</th><th>Confidence</th><th>Status</th><th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((a, i) => (
                  <tr key={a._id} className="anim-fade-up" style={{ animationDelay: `${i * 30}ms` }}
                      onClick={() => setSelected(a)}>
                    <td className="cell-mono cell-dim">{fmtDate(a.timestamp)}</td>
                    <td><span className="at-type">{atkIcon(a.attackType)} {a.attackType?.toUpperCase()}</span></td>
                    <td><span className="badge" style={{ background: sevBg(a.severity), color: sevColor(a.severity) }}>{a.severity}</span></td>
                    <td className="cell-mono cell-cyan">{a.sourceIP}</td>
                    <td className="cell-mono cell-cyan">{a.destinationIP}</td>
                    <td className="cell-mono cell-dim">{a.protocol?.toUpperCase()}</td>
                    <td>
                      <div className="conf-bar-wrap">
                        <div className="conf-bar" style={{ width: `${a.confidence * 100}%`, background: sevColor(a.severity) }} />
                      </div>
                      <span className="cell-mono cell-dim" style={{ fontSize: ".72rem" }}>{fmtPct(a.confidence)}</span>
                    </td>
                    <td>{a.acknowledged ? <span style={{ color: "var(--green)", fontSize: ".8rem" }}>✔ Ack</span> : <span className="pulse" style={{ color: "var(--orange)", fontSize: ".8rem", fontWeight: 600 }}>● New</span>}</td>
                    <td onClick={(e) => e.stopPropagation()}>
                      {!a.acknowledged && <button className="btn btn-primary btn-sm" onClick={() => handleAck(a._id)}>Ack</button>}
                      <button className="btn btn-danger btn-sm" style={{ marginLeft: 4 }} onClick={() => handleDel(a._id)}>✕</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {pg.pages > 1 && (
          <div className="at-pagination">
            <button className="btn btn-ghost btn-sm" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>← Prev</button>
            <span className="pg-info">Page {pg.page} of {pg.pages} — {pg.total} total</span>
            <button className="btn btn-ghost btn-sm" disabled={page >= pg.pages} onClick={() => setPage((p) => p + 1)}>Next →</button>
          </div>
        )}
      </div>
    </>
  );
}