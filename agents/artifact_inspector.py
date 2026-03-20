from agents.base import BaseAgent
from models import Finding


class ArtifactInspector(BaseAgent):
    name = "artifacts"

    def scan(self) -> list[Finding]:
        return []
