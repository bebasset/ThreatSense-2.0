"use client";

import { useEffect, useState } from "react";
import { apiFetch } from "@/lib/api";

type Asset = {
  id: string;
  kind: string;
  value: string;
  verified: boolean;
};

const NUCLEI_PRESETS: Record<string, any> = {
  "Default (Med+)": {
    severities: ["medium", "high", "critical"],
    exclude_tags: "dos,fuzz",
    rate_limit: 50,
    timeout: 10,
    retries: 1,
    wall_clock_timeout: 600,
    headless: false,
  },
  "Quick (High/Critical)": {
    severities: ["high", "critical"],
    exclude_tags: "dos,fuzz",
    rate_limit: 75,
    timeout: 8,
    retries: 1,
    wall_clock_timeout: 420,
    headless: false,
  },
  "CVE Focus": {
    severities: ["medium", "high", "critical"],
    tags: "cves",
    exclude_tags: "dos,fuzz",
    rate_limit: 40,
    timeout: 12,
    retries: 1,
    wall_clock_timeout: 900,
    headless: false,
  },
};

function safeJsonParse(input: string) {
  if (!input.trim()) return {};
  try {
    return JSON.parse(input);
  } catch {
    throw new Error('Parameters must be valid JSON (example: {"timeout":10}).');
  }
}

export default function AssetsPage() {
  const [token, setToken] = useState("");
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState("");

  const [assets, setAssets] = useState<Asset[]>([]);

  // Create asset form
  const [kind, setKind] = useState("domain");
  const [value, setValue] = useState("");

  // Default scan settings (used when clicking "Start Scan")
  const [presetKey, setPresetKey] =
    useState<keyof typeof NUCLEI_PRESETS>("Default (Med+)");
  const [scanType, setScanType] = useState("vuln_scan");
  const [plugin, setPlugin] = useState("nuclei_scan");
  const [paramsText, setParamsText] = useState(
    JSON.stringify(NUCLEI_PRESETS["Default (Med+)"], null, 2)
  );

  async function loadAssets(t: string) {
    setErr("");
    setLoading(true);
    try {
      const a = await apiFetch("/assets", {}, t);
      setAssets(a);
    } catch (e: any) {
      setErr(e?.message || "Failed to load assets.");
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
    loadAssets(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function createAsset() {
    setErr("");
    try {
      if (!value.trim()) throw new Error("Asset value is required (ex: example.com).");

      await apiFetch(
        "/assets",
        {
          method: "POST",
          body: JSON.stringify({ kind, value: value.trim() }),
        },
        token
      );

      setValue("");
      await loadAssets(token);
    } catch (e: any) {
      setErr(e?.message || "Failed to create asset.");
    }
  }

  async function startScan(assetId: string) {
    setErr("");
    try {
      const parameters = safeJsonParse(paramsText);

      await apiFetch(
        "/scans",
        {
          method: "POST",
          body: JSON.stringify({
            asset_id: assetId,
            scan_type: scanType,
            plugin,
            requires_approval: false,
            parameters,
          }),
        },
        token
      );

      alert("Scan queued!");
    } catch (e: any) {
      setErr(e?.message || "Failed to start scan.");
    }
  }

  return (
    <main style={{ padding: 24, maxWidth: 1100 }}>
      <h1 style={{ margin: 0 }}>Assets</h1>
      <p style={{ marginTop: 8, color: "#444" }}>
        Add targets (domains, IPs, log sources) and run scans against them.
      </p>

      <nav style={{ display: "flex", gap: 12, margin: "12px 0 18px" }}>
        <a href="/dashboard">Dashboard</a>
        <a href="/assets">Assets</a>
        <a href="/findings">Findings</a>
      </nav>

      {err && (
        <div
          style={{
            padding: 12,
            border: "1px solid #f3baba",
            background: "#fff4f4",
            borderRadius: 10,
          }}
        >
          <b>Error:</b> {err}
        </div>
      )}

      <section style={{ marginTop: 16, padding: 14, border: "1px solid #eee", borderRadius: 12 }}>
        <h2 style={{ margin: 0 }}>Add Asset</h2>
        <div style={{ display: "grid", gridTemplateColumns: "180px 1fr 180px", gap: 10, marginTop: 12 }}>
          <select style={inputStyle} value={kind} onChange={(e) => setKind(e.target.value)}>
            <option value="domain">domain</option>
            <option value="ip">ip</option>
            <option value="host">host</option>
            <option value="webapp">webapp</option>
            <option value="log_source">log_source</option>
            <option value="url">url</option>
          </select>
          <input
            style={inputStyle}
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder="example.com or https://example.com"
          />
          <button style={buttonStyle} onClick={createAsset}>
            Create
          </button>
        </div>
      </section>

      <section style={{ marginTop: 16, padding: 14, border: "1px solid #eee", borderRadius: 12 }}>
        <h2 style={{ marginTop: 0 }}>Default Scan Settings</h2>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
          <div>
            <label style={labelStyle}>Scan Type</label>
            <select style={inputStyle} value={scanType} onChange={(e) => setScanType(e.target.value)}>
              <option value="vuln_scan">vuln_scan</option>
              <option value="soc">soc</option>
              <option value="ptaas">ptaas</option>
            </select>

            <label style={labelStyle}>Nuclei Preset</label>
            <select
              style={inputStyle}
              value={presetKey as string}
              onChange={(e) => {
                const key = e.target.value as keyof typeof NUCLEI_PRESETS;
                setPresetKey(key);
                setParamsText(JSON.stringify(NUCLEI_PRESETS[key], null, 2));
                setPlugin("nuclei_scan");
                setScanType("vuln_scan");
              }}
            >
              {Object.keys(NUCLEI_PRESETS).map((k) => (
                <option key={k} value={k}>
                  {k}
                </option>
              ))}
            </select>

            <label style={labelStyle}>Plugin</label>
            <input
              style={inputStyle}
              value={plugin}
              onChange={(e) => setPlugin(e.target.value)}
              placeholder='nuclei_scan'
            />
          </div>

          <div>
            <label style={labelStyle}>Parameters (JSON)</label>
            <textarea
              style={{ ...inputStyle, height: 140, fontFamily: "monospace" }}
              value={paramsText}
              onChange={(e) => setParamsText(e.target.value)}
            />
          </div>
        </div>
      </section>

      <section style={{ marginTop: 18 }}>
        <h2>All Assets</h2>
        {loading ? (
          <div>Loading…</div>
        ) : assets.length === 0 ? (
          <div>No assets yet.</div>
        ) : (
          <table style={tableStyle}>
            <thead>
              <tr>
                <th style={thStyle}>Kind</th>
                <th style={thStyle}>Value</th>
                <th style={thStyle}>Verified</th>
                <th style={thStyle}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {assets.map((a) => (
                <tr key={a.id}>
                  <td style={tdStyle}>{a.kind}</td>
                  <td style={tdStyle}>{a.value}</td>
                  <td style={tdStyle}>{a.verified ? "Yes" : "No"}</td>
                  <td style={tdStyle}>
                    <button
                      style={{ ...buttonStyle, width: "auto", padding: "8px 10px" }}
                      onClick={() => startScan(a.id)}
                    >
                      Start Scan
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <button style={{ ...buttonStyle, marginTop: 18 }} onClick={() => loadAssets(token)}>
        Refresh
      </button>
    </main>
  );
}

const labelStyle: React.CSSProperties = {
  display: "block",
  fontSize: 12,
  color: "#444",
  marginTop: 10,
  marginBottom: 6,
};
const inputStyle: React.CSSProperties = {
  width: "100%",
  padding: "10px 12px",
  borderRadius: 10,
  border: "1px solid #ddd",
};
const buttonStyle: React.CSSProperties = {
  padding: "10px 12px",
  borderRadius: 10,
  border: "1px solid #111",
  background: "#111",
  color: "#fff",
  cursor: "pointer",
};
const tableStyle: React.CSSProperties = { width: "100%", borderCollapse: "collapse" };
const thStyle: React.CSSProperties = {
  textAlign: "left",
  borderBottom: "1px solid #eee",
  padding: "10px 8px",
  fontSize: 12,
  color: "#555",
};
const tdStyle: React.CSSProperties = {
  borderBottom: "1px solid #f2f2f2",
  padding: "10px 8px",
  fontSize: 13,
};
