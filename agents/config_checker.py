from agents.base import BaseAgent
from models import Finding


class ConfigChecker(BaseAgent):
    name = "config"

    def scan(self) -> list[Finding]:
        return []
