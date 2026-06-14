"""Format de résultat unique partagé par tous les checks (et toutes les phases).

L'idée directrice : chaque check, quel qu'il soit (header HTTP, TLS, DNS, et
demain un wrapper nuclei), rend une liste de `Finding`. Tout le reste de l'appli
— scoring, streaming, dashboard, historique — ne manipule que ce type-là.
"""
from __future__ import annotations

from collections import Counter
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


# Au-delà de N findings de MÊME (check_id, sévérité), les suivants ne pénalisent plus le
# score (anti-avalanche d'un check répétitif, ex. cookies × N). Cf. score_and_grade.
_MAX_SAME_PENALIZED = 3

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
    # --- couverture : True si ce finding signale que le check N'A PAS pu s'exécuter
    # (crash isolé par le runner, outil de pentest absent/timeout, hôte injoignable). Ce
    # n'est PAS un PASS : ça plafonne le grade (cf. score_and_grade) au lieu de le gonfler.
    unexecuted: bool = False

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
            "unexecuted": self.unexecuted,
            "title": self.title,
            "detail": self.detail,
            "recommendation": self.recommendation,
        }


# Grades du meilleur au pire — sert au plafonnement (un plafond ne fait que descendre).
_GRADE_ORDER = ["A+", "A", "B", "C", "D", "E", "F"]


def _grade_from_score(score: int) -> str:
    if score >= 95:
        return "A+"
    if score >= 85:
        return "A"
    if score >= 75:
        return "B"
    if score >= 65:
        return "C"
    if score >= 50:
        return "D"
    if score >= 35:
        return "E"
    return "F"


def _worst_grade(*grades: str) -> str:
    """Le pire (le plus bas) des grades fournis."""
    return max(grades, key=_GRADE_ORDER.index)


def score_and_grade(findings: list["Finding"]) -> tuple[int, str]:
    # Pénalité PLAFONNÉE par (check_id, sévérité) : au-delà de `_MAX_SAME_PENALIZED` findings
    # identiques (ex. 8 cookies tiers sans Secure/HttpOnly), les suivants ne pénalisent plus —
    # sinon un seul check répétitif fait tomber le score à 0 et écrase tout le diagnostic. Le
    # signal de gravité n'est PAS perdu : la pire sévérité plafonne le grade juste après.
    seen: Counter = Counter()
    penalty = 0
    for f in findings:
        w = _WEIGHTS[f.severity]
        if w == 0:
            continue
        key = (f.check_id, f.severity)
        seen[key] += 1
        if seen[key] <= _MAX_SAME_PENALIZED:
            penalty += w
    score = max(0, 100 - penalty)
    grade = _grade_from_score(score)

    # Plafond par PIRE SÉVÉRITÉ : un problème grave doit empêcher une note rassurante même
    # si le score brut reste haut (un seul fichier `.env` exposé ne peut pas valoir un « B »).
    severities = {f.severity for f in findings}
    if Severity.CRITICAL in severities:
        grade = _worst_grade(grade, "E")
    elif Severity.HIGH in severities:
        grade = _worst_grade(grade, "C")

    # Plafond par COUVERTURE INCOMPLÈTE : si un check a planté ou qu'un outil de pentest
    # n'a pas tourné (absent/timeout), on ne prétend pas à l'excellence — pas d'A/A+. Sinon
    # un scan où nuclei est absent afficherait « A+ » alors que rien n'a été testé.
    if any(getattr(f, "unexecuted", False) for f in findings):
        grade = _worst_grade(grade, "B")

    return score, grade


def summarize(findings: list["Finding"]) -> dict:
    counts = {s.value: 0 for s in Severity}
    for f in findings:
        counts[f.severity.value] += 1
    score, grade = score_and_grade(findings)
    # Checks qui n'ont pas pu s'exécuter (couverture partielle) — exposé au front pour une
    # bannière « scan incomplet », et reflété par le plafond de grade ci-dessus.
    incomplete = sorted({f.check_id for f in findings if getattr(f, "unexecuted", False)})
    return {"score": score, "grade": grade, "counts": counts, "total": len(findings),
            "incomplete": bool(incomplete), "unexecuted": incomplete}
