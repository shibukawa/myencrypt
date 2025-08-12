# syntax=docker/dockerfile:1

ARG GO_VERSION=1.24.5

FROM --platform=${BUILDPLATFORM} golang:${GO_VERSION} AS build
WORKDIR /src

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=latest

ENV CGO_ENABLED=1

RUN apt-get update && apt-get install -y \
    gcc-aarch64-linux-gnu \
    gcc-x86-64-linux-gnu \
    && rm -rf /var/lib/apt/lists/*

RUN --mount=type=cache,target=/go/pkg/mod/ \
    --mount=type=bind,source=go.sum,target=go.sum \
    --mount=type=bind,source=go.mod,target=go.mod \
    if [ "$TARGETARCH" = "amd64" ]; then \
        export CC=x86_64-linux-gnu-gcc; \
    elif [ "$TARGETARCH" = "arm64" ]; then \
        export CC=aarch64-linux-gnu-gcc; \
    fi && \
    go mod download -x

RUN --mount=type=cache,target=/go/pkg/mod/ \
    --mount=type=bind,target=. \
    if [ "$TARGETARCH" = "amd64" ]; then \
        export CC=x86_64-linux-gnu-gcc; \
    elif [ "$TARGETARCH" = "arm64" ]; then \
        export CC=aarch64-linux-gnu-gcc; \
    fi && \
    CGO_ENABLED=1 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -ldflags '-w -s -X "main.version=${VERSION}"' -o /bin/myencrypt ./cmd/myencrypt

FROM gcr.io/distroless/base-debian12 AS final

ENV MYENCRYPT_EXPOSE_PORT=14000 \
    MYENCRYPT_PROJECT_NAME=myencrypt \
    MYENCRYPT_INDIVIDUAL_CERT_TTL=168h \
    MYENCRYPT_CA_CERT_TTL=19200h \
    MYENCRYPT_ALLOWED_DOMAINS=localhost,*.localhost,*.test,*.example,*.invalid,app.localhost \
    MYENCRYPT_CERT_STORE_PATH=/data \
    MYENCRYPT_DATABASE_PATH=/data/myencrypt.db \
    MYENCRYPT_LOG_LEVEL=info

COPY --from=build /bin/myencrypt /bin/myencrypt

# Add health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["/bin/myencrypt", "healthcheck"]

EXPOSE 80

ENTRYPOINT [ "/bin/myencrypt" ]
CMD ["run"]
