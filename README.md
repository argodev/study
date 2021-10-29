# Study Notes

These are a collection of notes I've taken while working on learning various aspects of vulnerability science.

## Building/Serving

These notes are written in markdown and designed to be served/hosted/generated via `mkdocs`.

### Dependencies

```bash
$ python3 -m pip install --upgrade pip
$ python3 -m pip install mkdocs mkdocs-material \
                         mkdocs-git-revision-date-localized-plugin \
                         mkdocs-mermaid2-plugin \
                         mkdocs-with-pdf
```

### From Repository Root

```bash
$ mkdocs build
$ mkdocs serve
```

This will allow you to se the docs in a browser at http://localhost:8000

### To Generate a PDF

You will need to download/install the Chrome Driver

https://chromedriver.chromium.org/

I also needed to install the chromium browser (not chrome) via the following:

``` sh
$ sudo apt-get install chromium-browser
```

Run `$ ENABLE_PDF_EXPORT=1 mkdocs build` and a PDF will be generated.


### Make Your Own

More information on this documentation approach can be found at https://squidfunk.github.io/mkdocs-material


