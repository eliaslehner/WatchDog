from abc import ABC, abstractmethod
from pathlib import Path

from models import Finding


class BaseAgent(ABC):
    name: str = "base"

    def __init__(self, path: str, framework: str | None = None, target: str | None = None):
        self.path = Path(path)
        self.framework = framework
        self.target = target

    @abstractmethod
    def scan(self) -> list[Finding]:
        ...
