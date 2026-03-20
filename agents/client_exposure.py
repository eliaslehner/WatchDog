from agents.base import BaseAgent
from models import Finding


class ClientExposureAnalyzer(BaseAgent):
    name = "client-exposure"

    def scan(self) -> list[Finding]:
        return []
