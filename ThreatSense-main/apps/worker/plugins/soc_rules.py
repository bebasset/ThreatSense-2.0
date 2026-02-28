import json
import os
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any

from plugins.base import BasePlugin, PluginResult


class SocRules(BasePlugin):
    """
    Threat Sense SOCaaS MVP plugin (rule-based detections).

    Inputs:
      - asset_kind: "log_source" | "tenant" | "org" (not heavily used in MVP)
      - asset_value: identifier for the log source (e.g., "m365", "pfsense", "wazuh")

    params:
      - "events": list[dict]  (REQUIRED for this MVP plugin)
          Expected normalized keys (best effort):
            ts (ISO8601 string), source, event_type, user, ip, device, hostname, status, action
      - "window_minutes": int (default 15)
      - "thresholds": dict (optional overrides)
      - "artifacts_dir": str (default /tmp/threatsense_artifacts)
      - "run_id": str (optional)

    Output:
      - findings[] = alerts/detections with evidence + remediation guidance
      - artifact_path = path to stored normalized events JSON
    """

    name = "soc_rules"

    def run(self, asset_kind: str, asset_value: str, params: dict[str, Any]) -> PluginResult:
        events = params.get("events")
        if not isinstance(events, list) or not events:
            return PluginResult(
                findings=[{
                    "title": "SOC ingest: no events provided",
                    "severity": "info",
                    "category": "soc",
                    "evidence": "No events were passed to the SOC rules engine. Provide params['events'] as a list of normalized events.",
                    "remediation": "Set up a log ingestion route/connector (M365, Google Workspace, firewall logs, Wazuh agent).",
                }],
                artifact_path=None
            )

        window_minutes = int(params.get("window_minutes") or 15)
        thresholds = params.get("thresholds") or {}
        th_failed_login = int(thresholds.get("failed_login_per_user_ip") or 10)
        th_failed_login_global = int(thresholds.get("failed_login_global_per_ip") or 30)
        th_admin_events = int(thresholds.get("admin_actions_per_window") or 3)

        # Store events as artifact for evidence / audit trail
        artifacts_root = params.get("artifacts_dir") or "/tmp/threatsense_artifacts"
        os.makedirs(artifacts_root, exist_ok=True)

        run_id = params.get("run_id") or datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        artifact_path = os.path.join(artifacts_root, f"soc_events_{run_id}.json")

        with open(artifact_path, "w", encoding="utf-8") as f:
            json.dump(events, f, ensure_ascii=False, indent=2)

        # Normalize + filter to time window (best-effort)
        cutoff = datetime.utcnow() - timedelta(minutes=window_minutes)
        norm_events = []
        for e in events:
            ts = self._parse_ts(e.get("ts"))
            if ts is None:
                ts = datetime.utcnow()  # if missing, treat as current
            # keep only within window if ts is parseable
            if ts >= cutoff:
                norm_events.append({**e, "_ts": ts})

        # Run detections
        findings: list[dict] = []
        findings += self._detect_bruteforce_user_ip(norm_events, th_failed_login)
        findings += self._detect_bruteforce_global_ip(norm_events, th_failed_login_global)
        findings += self._detect_suspicious_admin_activity(norm_events, th_admin_events)
        findings += self._detect_new_admin_creation(norm_events)
        findings += self._detect_impossible_travel_hint(norm_events)

        if not findings:
            findings = [{
                "title": "SOC window summary: no high-signal alerts",
                "severity": "info",
                "category": "soc",
                "evidence": f"Processed {len(norm_events)} events within the last {window_minutes} minutes from source={asset_value}. No alerts fired.",
                "remediation": "Continue monitoring. Consider enabling more log sources for better coverage (M365, firewall, endpoint).",
            }]

        return PluginResult(findings=findings, artifact_path=artifact_path)

    # -------------------------
    # Detection rules (MVP)
    # -------------------------

    def _detect_bruteforce_user_ip(self, events: list[dict], threshold: int) -> list[dict]:
        """
        Detect many failed logins for same (user, ip) in window.
        """
        counts = defaultdict(int)
        for e in events:
            if e.get("event_type") in ("auth_failed", "login_failed", "failed_login"):
                user = e.get("user") or "unknown_user"
                ip = e.get("ip") or "unknown_ip"
                counts[(user, ip)] += 1

        findings = []
        for (user, ip), c in counts.items():
            if c >= threshold:
                findings.append({
                    "title": f"Potential brute force against user {user}",
                    "severity": "high",
                    "category": "soc.auth",
                    "evidence": f"{c} failed login attempts for user={user} from ip={ip} within the monitoring window.",
                    "remediation": "Block/limit the source IP, enforce MFA, review account lockout policy, and investigate the user’s account activity.",
                })
        return findings

    def _detect_bruteforce_global_ip(self, events: list[dict], threshold: int) -> list[dict]:
        """
        Detect many failed logins from a single IP across multiple users.
        """
        counts = defaultdict(int)
        users_by_ip = defaultdict(set)

        for e in events:
            if e.get("event_type") in ("auth_failed", "login_failed", "failed_login"):
                ip = e.get("ip") or "unknown_ip"
                user = e.get("user") or "unknown_user"
                counts[ip] += 1
                users_by_ip[ip].add(user)

        findings = []
        for ip, c in counts.items():
            if c >= threshold and len(users_by_ip[ip]) >= 3:
                findings.append({
                    "title": "Potential password spraying activity",
                    "severity": "high",
                    "category": "soc.auth",
                    "evidence
                    "remediation": "Block/limit the IP, enforce MFA, enable conditional access, and review authentication logs for successful logins from the same IP.",
                })
        return findings

    def _detect_suspicious_admin_activity(self, events: list[dict], threshold: int) -> list[dict]:
        """
        Detect bursts of privileged/admin actions.
        """
        admin_actions = 0
        examples = []

        for e in events:
            if e.get("event_type") in ("admin_action", "privileged_action"):
                admin_actions += 1
                if len(examples) < 5:
                    examples.append(self._event_brief(e))

        if admin_actions >= threshold:
            return [{
                "title": "Burst of privileged/admin actions detected",
                "severity": "medium",
                "category": "soc.privilege",
                "evidence": f"{admin_actions} privileged actions within the monitoring window. Examples: {examples}",
                "remediation": "Confirm changes are authorized. Review who performed the actions, validate MFA, and restrict admin roles to least privilege.",
            }]
        return []
        
    def _detect_new_admin_creation(self, events: list[dict]) -> list[dict]:
        """
        Detect creation of a new admin / privilege escalation events (best-effort).
        """
        matches = []
        for e in events:
            et = (e.get("event_type") or "").lower()
            action = (e.get("action") or "").lower()
            if et in ("user_role_changed", "admin_created", "privilege_granted") or "admin" in action and ("add" in action or "grant" in action):
                matches.append(self._event_brief(e))
        if matches:
            return [{
                "title": "New admin/privilege grant event detected",
                "severity": "high",
                "category": "soc.privilege",
                "evidence": f"Detected potential privilege escalation events. Examples: {matches[:5]}",
                "remediation": "Validate business justification, confirm change control ticket, review account security, and revert unauthorized privilege changes immediately.",
            }]
        return []
     "remediation": "Review user’s session activity, enforce MFA, check conditional access policies, and reset credentials if suspicious.",
                })
        return findings
     # -------------------------
    # Helpers
    # -------------------------

    def _parse_ts(self, ts_val: Any) -> datetime | None:
        if not ts_val:
            return None
        if isinstance(ts_val, datetime):
            return ts_val
        try:
            # Accept ISO strings with 'Z'
            s = str(ts_val).replace("Z", "+00:00")
            return datetime.fromisoformat(s).replace(tzinfo=None)
        except Exception:
            return None

    def _event_brief(self, e: dict) -> str:
        ts = e.get("ts", "na")
        user = e.get("user", "na")
        ip = e.get("ip", "na")
        et = e.get("event_type", "na")
        return f"{ts}:{et}:{user}@{ip}"
