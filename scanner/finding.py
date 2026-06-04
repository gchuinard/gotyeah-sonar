"""Format de résultat unique partagé par tous les checks (et toutes les phases).

L'idée directrice : chaque check, quel qu'il soit (header HTTP, TLS, DNS, et
demain un wrapper nuclei), rend une liste de `Finding`. Tout le reste de l'appli
— scoring, streaming, dashboard, historique — ne manipule que ce type-là.
"""
from __future__ import annotations

from dataclasses import dataclass, field
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
    SUBRESOURCE = "subresource"  # Phase 2 — en-têtes de sécurité sur les sous-ressources
    TECH = "tech"           # Phase 2 — technologies/versions détectées
    PORTS = "ports"         # Réseau — services/ports exposés (connect-scan borné)
    HTTP = "http"           # Méthodes HTTP (TRACE/PUT…) et durcissement verbe
    PENTEST = "pentest"     # Phase 3 — résultats du moteur nuclei
    ZAP = "zap"             # Phase 3 (bonus) — résultats d'OWASP ZAP (mode API)
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
    """Résultat d'un check.

    Deux formes coexistent (transition i18n) :

    * **Structurée** (cible) — le check ne fait que de la *détection* et laisse le
      texte humain au catalogue de présentation : il renseigne `code` (discriminant
      de résultat, ex. ``"absent"``/``"weak"``/``"ok"``) et `params` (valeurs
      d'interpolation : host, nom de cookie, version…). `title`/`detail`/
      `recommendation` restent vides ; la couche `scanner.i18n` les rend dans la
      langue demandée à partir de la clé ``(check_id, code)``.
    * **Externe** (ZAP / nuclei) — le résultat vient du catalogue d'un outil tiers :
      `catalog` (``"zap"``/``"nuclei"``) + `entry_id` (pluginId / template-id) servent
      de clé de contenu, et `source_text` porte le texte d'origine (anglais) utilisé
      en *fallback* si aucune entrée traduite n'existe.
    * **Legacy** — un `title` renseigné sans `code` (ancien historique, check non
      encore migré) : rendu tel quel, sans carte de remédiation.

    Seules `severity` (le score) et `check_id`/`category` (le routage) sont
    structurelles ; tout le reste est de la présentation.
    """
    check_id: str
    category: Category
    severity: Severity
    title: str = ""
    detail: str = ""
    recommendation: str = ""
    evidence: Optional[str] = None
    # --- i18n : détection structurée (le texte humain vit dans le catalogue) ---
    code: str = ""                              # result_code : discriminant DANS un check_id
    params: dict = field(default_factory=dict)  # valeurs d'interpolation (host, value, count…)
    catalog: Optional[str] = None               # "zap" | "nuclei" | None (= maison, clé = check_id)
    entry_id: Optional[str] = None              # pluginId / template-id (clé de contenu stable)
    source_text: Optional[dict] = None          # {title, detail, recommendation, refs[]} langue d'origine

    def as_dict(self) -> dict:
        """Sérialise la forme structurée (c'est ce qui est streamé et persisté).

        On conserve `title`/`detail`/`recommendation` : vides pour un check migré,
        renseignés pour un finding legacy — ce qui garde l'ancien historique lisible.
        """
        return {
            "check_id": self.check_id,
            "category": self.category.value,
            "severity": self.severity.value,
            "code": self.code,
            "params": self.params,
            "evidence": self.evidence,
            "catalog": self.catalog,
            "entry_id": self.entry_id,
            "source_text": self.source_text,
            "title": self.title,
            "detail": self.detail,
            "recommendation": self.recommendation,
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
