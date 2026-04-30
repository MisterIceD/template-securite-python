# Template code Sécurité Python

## Description

Projet contenant les modèles de TP pour le cours de sécurité Python de 4e année de l'ESGI.

## Installation

Faire un fork puis un clone du projet :

```bash
git clone git@github.com:<VotreNom>/template-securite-python.git
```

Installer les dépendances :

```bash
cd template-securite-python
poetry lock
poetry install --no-root
```

## Utilisation

Lancer le projet :

TP1
```bash
poetry run python -m src.tp1.main
```

TP2
```bash
poetry run python -m tp2.main -f .\src\tp2\shellcode.txt
```

TP3
```bash
poetry run python -m src.tp3.main -c {numéro du challenge allant de 1 à 5}
```

TP4
```bash
poetry run python -m src.tp4.main
```
