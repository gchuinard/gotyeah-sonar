"""Importer un module de check ici suffit à enregistrer ses @check.

Le runner fait `from . import checks`, ce qui exécute ces imports et peuple le
registre. Pour ajouter une famille de checks : crée le fichier puis ajoute-le ici.
"""

from . import (
    cookies,  # noqa: F401  Phase 1
    cors,  # noqa: F401  Phase 2
    dns,  # noqa: F401  Phase 1
    exposed,  # noqa: F401  Phase 2
    headers,  # noqa: F401  Phase 1
    leaks,  # noqa: F401  Phase 2 — fuites & well-known
    methods,  # noqa: F401  Phase 2 — méthodes HTTP (TRACE/PUT…)
    mixed,  # noqa: F401  Phase 2
    nuclei,  # noqa: F401  Phase 3
    ports,  # noqa: F401  Réseau — ports/services exposés
    redirect,  # noqa: F401  Phase 1 — redirection HTTP → HTTPS
    subresources,  # noqa: F401  Phase 2
    takeover,  # noqa: F401  Réseau — subdomain takeover (CNAME dangling)
    tech,  # noqa: F401  Phase 2
    tls,  # noqa: F401  Phase 1
    zap,  # noqa: F401  Phase 3 (bonus)
)
