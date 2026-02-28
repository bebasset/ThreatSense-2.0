"use client";

import { useEffect, useMemo, useState } from "react";
import { apiFetch } from "@/lib/api";

type Asset = {
  id: string;
  kind: string;
  value: string;
  verified: boolean;
};

type Scan = {
  id: string;
  status: string;
  scan_type: string;
  plugin: string;
};

function safeJsonParse(input: string) {
  if (!input.trim()) return {};
  try {
    return JSON.parse(input);
  } catch {
    throw new Error("Parameters must be valid JSON (example: {\"ports\":\"1-1000\"})");
  }
}

export default function DashboardPage() {
  const [token, setToken] = useState("");
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState("");
  const [requiresApproval, setRequiresApproval] = useState(false);

  const [assets, setAssets] = useState<Asset[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);

  // Quick scan form
  const [assetId, setAssetId] = useState("");
  // AFTER (Nuclei default)
  const [scanType, setScanType] = useState<"vuln_scan" | "soc" | "ptaas">("vuln_scan");
  const [plugin, setPlugin] = useState("nuclei_scan");
  const [paramsText, setParamsText] = useState(`{
    "severities": ["medium","high","critical"],
    "exclude_tags": "dos,fuzz",
    "rate_limit": 50,
    "timeout": 10,
    "retries": 1,
    "wall_clock_timeout": 600,
    "headless": false
}`);

  const recentScans = useMemo(() => scans.slice(0, 10), [scans]);

  async function loadAll(t: string) {
    setErr("");
    setLoading(true);
    try {
      const [a, s] = await Promise.all([
        apiFetch("/assets", {}, t),
        apiFetch("/scans", {}, t),
      ]);
      setAssets(a);
      setScans(s);
      if (!assetId && a?.length) setAssetId(a[0].id);
    } catch (e: any) {
      setErr(e?.message || "Failed to load dashboard.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    const t = localStorage.getItem("ts_token") || "";
    if (!t) {
      window.location.href = "/login";
      return;
    }
    setToken(t);
    loadAll(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function startScan() {
    setErr("");
    try {
      if (!assetId) throw new Error("Select an asset first.");
      const parameters = safeJsonParse(paramsText);

      await apiFetch(
        "/scans",
        {
          method: "POST",
          body: JSON.stringify({
            asset_id: assetId,
            scan_type: scanType,
            plugin,
            requires_approval: requiresApproval,
            parameters,
          }),
        },
        token
      );

      await loadAll(token);
    } catch (e: any) {
      setErr(e?.message || "Failed to start scan.");
    }
  }

  return (
    <main style={{ padding: 24, maxWidth: 1100 }}>
      <h1 style={{ fontSize: 40, margin: 0 }}>ThreatSense</h1>
      <p style={{ marginTop: 8 }}>
        Welcome. Use the navigation to access the app.
      </p>

      <nav style={{ display: "flex", gap: 12, margin: "12px 0 18px" }}>
        <a href="/login">Login</a>
        <a href="/dashboard">Dashboard</a>
        <a href="/assets">Assets</a>
        <a href="/findings">Findings</a>
      </nav>

      {err && (
        <div style={{ padding: 12, border: "1px solid #f3baba", background: "#fff4f4", borderRadius: 10 }}>
          <b>Error:</b> {err}
        </div>
      )}

      <section style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 12, marginTop: 16 }}>
        <StatCard title="Assets" value={assets.length} />
        <StatCard title="Scans" value={scans.length} />
        <StatCard title="SOC/PTaaS" value={"via Scans"} />
      </section>

      <section style={{ marginTop: 22, padding: 14, border: "1px solid #eee", borderRadius: 12 }}>
        <h2 style={{ margin: 0 }}>Run a Scan</h2>
        <p style={{ marginTop: 6, color: "#444" }}>
          Start vulnerability scans (SOCaaS-style scanning) using your worker plugins. PTaaS can be represented as a scan type
          until engagement endpoints are added.
        </p>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginTop: 12 }}>
          <div>
            <label style={labelStyle}>Asset</label>
            <select style={inputStyle} value={assetId} onChange={(e) => setAssetId(e.target.value)}>
              <option value="">Select…</option>
              {assets.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.kind}: {a.value}
                </option>
              ))}
            </select>

            <label style={labelStyle}>Scan Type</label>
            <select
              style={inputStyle}
              value={scanType}
              onChange={(e) => setScanType(e.target.value as any)}
            >
              <option value="vuln_scan">vuln_scan (Vulnerability Scanning)</option>
              <option value="soc">soc (SOC Detection Run)</option>
              <option value="ptaas">ptaas (PTaaS Workflow Placeholder)</option>
            </select>

            <label style={labelStyle}>Plugin</label>
            <input
              style={inputStyle}
              value={plugin}
              onChange={(e) => setPlugin(e.target.value)}
              placeholder='Example: "nmap_stub" or "nuclei"'
            />
            <label style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 10 }}>
            <input
            type="checkbox"
            checked={requiresApproval}
            onChange={(e) => setRequiresApproval(e.target.checked)}
            />
             Requires approval
            </label>
            <label style={{ ...labelStyle, display: "flex", alignItems: "center", gap: 8 }}>
              <input
                type="checkbox"
                checked={requiresApproval}
                onChange={(e) => setRequiresApproval(e.target.checked)}
              />
              Requires approval (sets status to awaiting_approval)
            </label>
          </div>

          <div>
            <label style={labelStyle}>Parameters (JSON)</label>
            <textarea
              style={{ ...inputStyle, height: 140, fontFamily: "monospace" }}
              value={paramsText}
              onChange={(e) => setParamsText(e.target.value)}
            />

            <button style={buttonStyle} onClick={startScan} disabled={loading}>
              Start Scan
            </button>

            <button
              style={{ ...buttonStyle, background: "#fff", color: "#111", marginTop: 8 }}
              onClick={() => loadAll(token)}
              disabled={loading}
            >
              Refresh
            </button>
          </div>
        </div>
      </section>

      <section style={{ marginTop: 22 }}>
        <h2 style={{ marginBottom: 10 }}>Recent Scans</h2>
        {loading ? (
          <div>Loading…</div>
        ) : (
          <table style={tableStyle}>
            <thead>
              <tr>
                <th style={thStyle}>Status</th>
                <th style={thStyle}>Type</th>
                <th style={thStyle}>Plugin</th>
                <th style={thStyle}>Scan ID</th>
              </tr>
            </thead>
            <tbody>
              {recentScans.length === 0 ? (
                <tr>
                  <td style={tdStyle} colSpan={4}>No scans yet.</td>
                </tr>
              ) : (
                recentScans.map((s) => (
                  <tr key={s.id}>
                    <td style={tdStyle}>{s.status}</td>
                    <td style={tdStyle}>{s.scan_type}</td>
                    <td style={tdStyle}>{s.plugin}</td>
                    <td style={tdStyle} title={s.id}>{s.id}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        )}
      </section>
    </main>
  );
}

function StatCard({ title, value }: { title: string; value: any }) {
  return (
    <div style={{ border: "1px solid #eee", borderRadius: 12, padding: 14 }}>
      <div style={{ fontSize: 12, color: "#444" }}>{title}</div>
      <div style={{ fontSize: 34, fontWeight: 700, marginTop: 6 }}>{value}</div>
    </div>
  );
}

const labelStyle: React.CSSProperties = { display: "block", fontSize: 12, color: "#444", marginTop: 10, marginBottom: 6 };
const inputStyle: React.CSSProperties = { width: "100%", padding: "10px 12px", borderRadius: 10, border: "1px solid #ddd" };
const buttonStyle: React.CSSProperties = { width: "100%", padding: "10px 12px", borderRadius: 10, border: "1px solid #111", background: "#111", color: "#fff", cursor: "pointer", marginTop: 12 };
const tableStyle: React.CSSProperties = { width: "100%", borderCollapse: "collapse" };
const thStyle: React.CSSProperties = { textAlign: "left", borderBottom: "1px solid #eee", padding: "10px 8px", fontSize: 12, color: "#555" };
const tdStyle: React.CSSProperties = { borderBottom: "1px solid #f2f2f2", padding: "10px 8px", fontSize: 13 };
