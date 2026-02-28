"use client";

export default function HomePage() {
  return (
    <main style={{ padding: 24 }}>
      <h1>ThreatSense</h1>
      <p>Welcome. Use the navigation to access the app.</p>

      <div style={{ marginTop: 16, display: "flex", gap: 12 }}>
        <a href="/login">Login</a>
        <a href="/dashboard">Dashboard</a>
        <a href="/assets">Assets</a>
        <a href="/findings">Findings</a>
      </div>
    </main>
  );
}
