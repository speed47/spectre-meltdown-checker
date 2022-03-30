FROM alpine:latest

RUN apk --update --no-cache add kmod binutils grep perl zstd wget sharutils unzip sqlite procps coreutils iucode-tool gzip xz bzip2 lz4

COPY spectre-meltdown-checker.sh /

ENTRYPOINT ["/spectre-meltdown-checker.sh"]
