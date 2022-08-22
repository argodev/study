# Study Notes

These are a collection of notes I've taken while working on learning various aspects of vulnerability science.

The "pretty" version of these notes is available at https://robgillen.com/study/

Assets (scripts, files, etc.) that I generate while working through the various topics here are available in teh 


## Helpers

This page has some helpful "lookups" for finding icons: https://squidfunk.github.io/mkdocs-material/reference/icons-emojis/


<!-- ## Building/Serving

These notes are written in markdown and designed to be served/hosted/generated via `mkdocs`.

### Dependencies

```bash
$ python3 -m pip install --upgrade pip
$ python3 -m pip install --upgrade mkdocs mkdocs-material \
                         mkdocs-git-revision-date-localized-plugin \
                         mkdocs-with-pdf
```
                         <!-- mkdocs-mermaid2-plugin \ -->


<!-- ### From Repository Root

```bash
$ mkdocs build
$ mkdocs serve
```

This will allow you to se the docs in a browser at http://localhost:8000
 -->


<!-- You will need to download/install the Chrome Driver

https://chromedriver.chromium.org/

I also needed to install the chromium browser (not chrome) via the following:

``` sh
$ sudo apt-get install chromium-browser
```
 -->



<!-- # Run with Docker

This is all set to run and build the documentation site with Docker. Because of the plugins needed, we need to build our own docker image and then use that image for subsequent work. The following commands should all be run from the root of the project. We assume you have docker installed and properly configured.

```bash
# Build the customized image
# should only need to do this once
docker build -t squidfunk/mkdocs-material .

# build/serve the documentation locally
# monitors local dir and re-generates automagically
docker run --rm -it -p 8000:8000 -v ${PWD}:/docs squidfunk/mkdocs-material

# just build the documentation
docker run --rm -it -v ${PWD}:/docs squidfunk/mkdocs-material build

``` -->
