"use client";
import { useState } from "react";
import { apiFetch } from "@/lib/api";

export default function LoginPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [err, setErr] = useState("");

  async function onLogin() {
    setErr("");
    try {
      const data = await apiFetch("/auth/login", {
        method: "POST",
        body: JSON.stringify({ email, password })
      });
      localStorage.setItem("ts_token", data.access_token);
      window.location.href = "/dashboard";
    } catch (e: any) {
      setErr(e.message);
    }
  }

  return (
    <main style={{ padding: 24 }}>
      <h1>Threat Sense Login</h1>
      <div style={{ marginTop: 12 }}>
        <input value={email} onChange={(e) => setEmail(e.target.value)} placeholder="email" />
      </div>
      <div style={{ marginTop: 12 }}>
        <input value={password} onChange={(e) => setPassword(e.target.value)} placeholder="password" type="password" />
      </div>
      <button style={{ marginTop: 12 }} onClick={onLogin}>Login</button>
      {err && <p style={{ marginTop: 12 }}>{err}</p>}
    </main>
  );
}
