"""Importer un module de check ici suffit à enregistrer ses @check.

Le runner fait `from . import checks`, ce qui exécute ces imports et peuple le
registre. Pour ajouter une famille de checks : crée le fichier puis ajoute-le ici.
"""
from . import headers   # noqa: F401  Phase 1
from . import cookies   # noqa: F401  Phase 1
from . import tls       # noqa: F401  Phase 1
from . import dns       # noqa: F401  Phase 1
from . import exposed   # noqa: F401  Phase 2
from . import cors      # noqa: F401  Phase 2
from . import mixed     # noqa: F401  Phase 2
from . import subresources  # noqa: F401  Phase 2
from . import tech      # noqa: F401  Phase 2
from . import nuclei    # noqa: F401  Phase 3
