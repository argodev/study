FROM squidfunk/mkdocs-material
RUN pip install mkdocs-git-revision-date-localized-plugin

# the following are just needed for the PDF stuff... if you don't
# need them, you can comment this out and it will make your image build 
# both smaller and take less time to assemble
RUN apk add --update build-base libffi-dev zlib-dev jpeg-dev
RUN pip install mkdocs-with-pdf

RUN apk add --update gtk+3.0-dev


# Add tagged repos as well as the edge repo so that we can selectively install edge packages
RUN \
    echo "@main http://dl-cdn.alpinelinux.org/alpine/v3.12/main" >> /etc/apk/repositories && \
    echo "@community http://dl-cdn.alpinelinux.org/alpine/v3.12/community" >> /etc/apk/repositories

RUN apk add --update ttf-roboto@community ttf-roboto-mono@community

#3.13