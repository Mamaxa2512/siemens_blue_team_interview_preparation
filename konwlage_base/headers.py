from core.models import Severity


class RawFinding:
    name: str
    severity: Severity
    description: str
    impact: str