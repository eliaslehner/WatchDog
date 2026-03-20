from agents.base import BaseAgent
from models import Finding


class DepChecker(BaseAgent):
    name = "dependencies"

    def scan(self) -> list[Finding]:
        return []
