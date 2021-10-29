# Study Notes

These are a collection of notes I've taken while working on learning various aspects of vulnerability science.

## Building/Serving

These notes are written in markdown and designed to be served/hosted/generated via `mkdocs`.

### Dependencies

```bash
$ python3 -m pip install --upgrade pip
$ python3 -m pip install mkdocs mkdocs-material \
                         mkdocs-git-revision-date-localized-plugin \
                         mkdocs-with-pdf
```
                         <!-- mkdocs-mermaid2-plugin \ -->


### From Repository Root

```bash
$ mkdocs build
$ mkdocs serve
```

This will allow you to se the docs in a browser at http://localhost:8000

### To Generate a PDF

Run `$ ENABLE_PDF_EXPORT=1 mkdocs build` and a PDF will be generated.[^1]

  [^1]:
    Most of the diagrams here had been "drawn" with inline markdown desinged to be interpreted
    by Mermaid. While this works fine (given the Mermaind2 plugin), it doesn't work well at
    all when attempting to render a PDF (yes, I tried the headless render with chromium). 
    Therefore, I went to https://mermaid.live/ and dropped my markdown in, saved the resulting
    PNG files, and referenced those in my documentation pages.


<!-- You will need to download/install the Chrome Driver

https://chromedriver.chromium.org/

I also needed to install the chromium browser (not chrome) via the following:

``` sh
$ sudo apt-get install chromium-browser
```
 -->




### Make Your Own

More information on this documentation approach can be found at https://squidfunk.github.io/mkdocs-material

Other things to look at:

* https://github.com/orzih/mkdocs-with-pdf
* https://mermaid.live/
* http://bwmarrin.github.io/MkDocsPlus 
