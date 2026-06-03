"""Package `scanner` — moteur de scan et familles de checks.

Découpage :
  finding.py    le format de sortie commun (Finding + sévérités + scoring)
  registry.py   le décorateur @check et l'inventaire global des checks
  runner.py     le moteur : lance les checks en // et émet les events
  checks/       une famille de checks par fichier (headers, cookies, tls, dns…)

Voir le README pour le principe directeur : « tout est un Finding ».
"""
