"""Format de résultat unique partagé par tous les checks (et toutes les phases).

L'idée directrice : chaque check, quel qu'il soit (header HTTP, TLS, DNS, et
demain un wrapper nuclei), rend une liste de `Finding`. Tout le reste de l'appli
— scoring, streaming, dashboard, historique — ne manipule que ce type-là.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    PASS = "pass"  # configuration correcte (point vert), ne pénalise pas le score


class Category(str, Enum):
    HEADERS = "headers"
    COOKIES = "cookies"
    TLS = "tls"
    DNS = "dns"
    EXPOSURE = "exposure"   # Phase 2 — fichiers/chemins sensibles exposés
    CORS = "cors"           # Phase 2 — partage de ressources cross-origin
    CONTENT = "content"     # Phase 2 — contenu mixte (ressources http sur page https)
    TECH = "tech"           # Phase 2 — technologies/versions détectées
    TRANSPORT = "transport"
    INFO = "info"


# Poids retirés du score (sur 100) par finding selon sa sévérité.
_WEIGHTS = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 15,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
    Severity.INFO: 0,
    Severity.PASS: 0,
}


@dataclass
class Finding:
    check_id: str
    category: Category
    severity: Severity
    title: str
    detail: str = ""
    recommendation: str = ""
    evidence: Optional[str] = None

    def as_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "category": self.category.value,
            "severity": self.severity.value,
            "title": self.title,
            "detail": self.detail,
            "recommendation": self.recommendation,
            "evidence": self.evidence,
        }


def score_and_grade(findings: list["Finding"]) -> tuple[int, str]:
    penalty = sum(_WEIGHTS[f.severity] for f in findings)
    score = max(0, 100 - penalty)
    if score >= 95:
        grade = "A+"
    elif score >= 85:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 65:
        grade = "C"
    elif score >= 50:
        grade = "D"
    elif score >= 35:
        grade = "E"
    else:
        grade = "F"
    return score, grade


def summarize(findings: list["Finding"]) -> dict:
    counts = {s.value: 0 for s in Severity}
    for f in findings:
        counts[f.severity.value] += 1
    score, grade = score_and_grade(findings)
    return {"score": score, "grade": grade, "counts": counts, "total": len(findings)}
