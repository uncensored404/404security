# Contribuer a 404SECURITY

## Environnement de dev

    git clone https://github.com/404sec/404security.git
    cd 404security
    python3 -m venv .venv && . .venv/bin/activate
    pip install -r requirements.txt
    pip install flake8 pytest

## Avant chaque pull request

1. `flake8 core modules tests main.py --max-line-length=100`
2. `python -m pytest tests/ -v` — tous les tests doivent passer
3. La CI GitHub doit etre verte

## Conventions

- Python 3.11+, commentaires en francais, courts et utiles
- Un module = un dossier dans `modules/<nom>/` avec son `__init__.py`
- Toute nouvelle detection doit etre testable : logique pure separee de l'I/O
- Les nouvelles regles de correlation vont dans `rules/correlation.yaml`
- Les nouvelles signatures de bannieres vulnerables vont dans
  `modules/vulnscan/cve_db.json`

## Signaler un bug

Ouvre une issue avec : version de l'OS, logs pertinents (`data/events.db`),
etapes de reproduction. Ne colle jamais d'IP reelles ni de donnees sensibles.

## Licence

Toute contribution est soumise a la licence GPL-3.0 du projet.
