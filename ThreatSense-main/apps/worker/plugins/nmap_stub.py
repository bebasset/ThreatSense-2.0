from plugins.base import BasePlugin, PluginResult

class NmapStub(BasePlugin):
    name = "nmap_stub"

    def run(self, asset_kind: str, asset_value: str, params: dict) -> PluginResult:
        # Placeholder: mimics a scan result to prove pipeline works.
        findings = [
            {
                "title": f"Exposure check for {asset_value}",
                "severity": "info",
                "category": "exposure",
                "evidence": f"Stub scan completed for {asset_kind}:{asset_value}.",
                "remediation": "Replace stub with real scanner plugin.",
            }
        ]
        return PluginResult(findings=findings, artifact_path=None)
