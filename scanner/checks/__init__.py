"""Importer un module de check ici suffit à enregistrer ses @check.

Le runner fait `from . import checks`, ce qui exécute ces imports et peuple le
registre. Pour ajouter une famille de checks : crée le fichier puis ajoute-le ici.
"""
from . import headers  # noqa: F401
from . import cookies  # noqa: F401
from . import tls      # noqa: F401
from . import dns      # noqa: F401
