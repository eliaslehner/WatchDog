from agents.base import BaseAgent
from models import Finding


class SecretScanner(BaseAgent):
    name = "secrets"

    def scan(self) -> list[Finding]:
        return []
