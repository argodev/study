# Cogitation - A Place for Learning and Thinking

This is a jupyter-book based site.

## Conda-Based setup

```bash
conda list -e > requirements.txt

conda create --name <env> --file requirements.txt

jupyter-book build ./docs

ghp-import -n -p -f _build/html

git subtree push --prefix _build/html origin gh-pages
```

## Pure-Python Setup

```bash
# install virtual environment
python3 -m venv .venv

# activate it
. .venv/bin/activate

# install packages
pip install -r requirements.txt

# build the site/book
jupyter-book build ./docs

# publish the site
ghp-import -n -p -f docs/_build/html
```

## One-time utilities/tips/notes

```bash
# create the book
jupyter-book create ./docs

pip install ghp-import

ghp-import -n -p -f docs/_build/html

env1/bin/python -m pip freeze > requirements.txt
env2/bin/python -m pip install -r requirements.txt
```
