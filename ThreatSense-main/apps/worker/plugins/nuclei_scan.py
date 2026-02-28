import json
import os
import shutil
import subprocess
import tempfile
from datetime import datetime
from typing import Any

from plugins.base import BasePlugin, PluginResult


class NucleiScan(BasePlugin):
    """
    Nuclei-based vulnerability scanner plugin.

    Expected inputs:
      - asset_kind: "url" | "domain" | "ip" (domains/IPs will be coerced to a URL if needed)
      - asset_value: target string

    params (all optional):
      - "target_url": override the URL target (recommended for web apps)
      - "severities": ["low","medium","high","critical"] (default: medium+)
      - "tags": "cves,misconfig,exposed-panels" (optional)
      - "exclude_tags": "dos,fuzz" (optional; safety filter)
      - "rate_limit": 50 (default)
      - "timeout": 10 (seconds per request; default)
      - "retries": 1 (default)
      - "templates_dir": "/opt/nuclei-templates" (default)
      - "headless": False (default)  # keep false for MVP safety/complexity
    """

    name = "nuclei_scan"

    def run(self, asset_kind: str, asset_value: str, params: dict[str, Any]) -> PluginResult:
        if not self._nuclei_exists():
            # Fail with a clear message so you know the worker image needs nuclei installed.
            return PluginResult(
                findings=[{
                    "title": "Nuclei binary not installed in worker image",
                    "severity": "high",
                    "category": "scanner_error",
                    "evidence": "The 'nuclei' executable was not found on PATH. Install nuclei in apps/worker/Dockerfile.",
                    "remediation": "Install ProjectDiscovery nuclei and templates in the worker container.",
                }],
                artifact_path=None
            )

        target = self._coerce_target(asset_kind, asset_value, params)

        severities = params.get("severities") or ["medium", "high", "critical"]
        tags = params.get("tags")
        exclude_tags = params.get("exclude_tags") or "dos,fuzz"  # sensible default
        rate_limit = int(params.get("rate_limit") or 50)
        timeout = int(params.get("timeout") or 10)
        retries = int(params.get("retries") or 1)
        templates_dir = params.get("templates_dir") or "/opt/nuclei-templates"
        headless = bool(params.get("headless") or False)

        # Artifacts
        artifacts_root = params.get("artifacts_dir") or "/tmp/threatsense_artifacts"
        os.makedirs(artifacts_root, exist_ok=True)

        run_id = params.get("run_id") or datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        out_path = os.path.join(artifacts_root, f"nuclei_{run_id}.jsonl")

        # Build nuclei command
        cmd = [
            "nuclei",
            "-u", target,
            "-jsonl",
            "-o", out_path,
            "-severity", ",".join(severities),
            "-rl", str(rate_limit),
            "-timeout", str(timeout),
            "-retries", str(retries),
            "-silent",
        ]

        # Use templates dir if present; otherwise nuclei will use its default location
        if templates_dir and os.path.isdir(templates_dir):
            cmd += ["-t", templates_dir]

        if tags:
            cmd += ["-tags", str(tags)]

        if exclude_tags:
            cmd += ["-exclude-tags", str(exclude_tags)]

        # Headless mode is powerful but increases complexity and risk; keep off unless you know you need it.
        if headless:
            cmd += ["-headless"]

        # Run nuclei safely (bounded execution)
        # Hard stop wall-clock timeout to avoid stuck scans.
        wall_clock_timeout = int(params.get("wall_clock_timeout") or 600)  # 10 mins default

        try:
            subprocess.run(
                cmd,
                check=False,                # nuclei returns non-zero sometimes even with output
                stdout=subprocess.DEVNULL,  # keep worker logs clean; artifacts contain evidence
                stderr=subprocess.DEVNULL,
                timeout=wall_clock_timeout,
            )
        except subprocess.TimeoutExpired:
            return PluginResult(
                findings=[{
                    "title": "Nuclei scan timed out",
                    "severity": "medium",
                    "category": "scanner_error",
                    "evidence": f"Scan exceeded wall_clock_timeout={wall_clock_timeout}s for target={target}.",
                    "remediation": "Reduce scope, lower templates, or increase wall_clock_timeout cautiously.",
                }],
                artifact_path=out_path if os.path.exists(out_path) else None
            )
        except Exception as e:
            return PluginResult(
                findings=[{
                    "title": "Nuclei scan execution error",
                    "severity": "high",
                    "category": "scanner_error",
                    "evidence": f"Exception while running nuclei: {type(e).__name__}: {e}",
                    "remediation": "Check worker container logs and nuclei installation.",
                }],
                artifact_path=out_path if os.path.exists(out_path) else None,
                )
