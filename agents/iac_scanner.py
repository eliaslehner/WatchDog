from agents.base import BaseAgent
from models import Finding


class IacScanner(BaseAgent):
    name = "iac"

    def scan(self) -> list[Finding]:
        return []
