# Study Notes

These are a collection of notes I've taken while working on learning various aspects of vulnerability science.

## Building/Serving

These notes are written in markdown and designed to be served/hosted/generated via `mkdocs`.

### Dependencies

```bash
$ python3 -m pip install --upgrade pip
$ python3 -m pip install mkdocs mkdocs-material \
                         mkdocs-git-revision-date-localized-plugin \
                         mkdocs-mermaid2-plugin
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

Run `$ ENABLE_PDF_EXPORT=1 mkdocs build` and a PDF will be generated.


### Make Your Own

More information on this documentation approach can be found at https://squidfunk.github.io/mkdocs-material


