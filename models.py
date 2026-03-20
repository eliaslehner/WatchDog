from dataclasses import dataclass
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"


@dataclass
class Finding:
    severity: Severity
    scanner: str
    file_path: str
    line: int
    description: str
    context: str = ""
    reasoning: str = ""
