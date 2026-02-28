from dataclasses import dataclass
from typing import Any

@dataclass
class PluginResult:
    findings: list[dict]
    artifact_path: str | None = None

class BasePlugin:
    name: str = "base"

    def run(self, asset_kind: str, asset_value: str, params: dict[str, Any]) -> PluginResult:
        raise NotImplementedError
