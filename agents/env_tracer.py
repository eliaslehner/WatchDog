from agents.base import BaseAgent
from models import Finding


class EnvTracer(BaseAgent):
    name = "env-flow"

    def scan(self) -> list[Finding]:
        return []
