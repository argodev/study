# Study Notes

These are a collection of notes I've taken while working on learning various aspects of vulnerability science.

## Building/Serving

These notes are written in markdown and designed to be served/hosted/generated via `mkdocs`.

### Dependencies

```bash
$ python3 -m pip install --upgrade pip
$ python3 -m pip install mkdocs mkdocs-material
```

### From Repository Root

```bash
$ mkdocs build
$ mkdocs serve
```

This will allow you to se the docs in a browser at http://localhost:8000

### To Generate a PDF

```bash
$ python3 -m pip install mkdocs-with-pdf
```

Edit the `mkdocs.yml` file and add:

```yaml
- plugins:
    - with-pdf
```

The next time you run `mkdocs build`, a PDF will be generated.


### Make Your Own

More information on this documentation approach can be found at https://squidfunk.github.io/mkdocs-material


