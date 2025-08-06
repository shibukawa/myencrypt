# syntax=docker/dockerfile:1

ARG GO_VERSION=1.24.5

FROM --platform=${BUILDPLATFORM} golang:${GO_VERSION} AS build
WORKDIR /src

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=latest

ENV CGO_ENABLED=1 \
    GOOS=$TARGETOS \
    GOARCH=$TARGETARCH

RUN apt-get update && \
    if [ "$TARGETARCH" = "arm64" ]; then \
        apt-get install -y gcc-aarch64-linux-gnu libc6-dev-arm64-cross ; \
    elif [ "$TARGETARCH" = "amd64" ]; then \
        apt-get install -y build-essential ; \
    fi

RUN --mount=type=cache,target=/go/pkg/mod/ \
    --mount=type=bind,source=go.sum,target=go.sum \
    --mount=type=bind,source=go.mod,target=go.mod \
    if [ "$TARGETARCH" = "arm64" ]; then \
        CC=aarch64-linux-gnu-gcc go mod download -x ; \
    elif [ "$TARGETARCH" = "amd64" ]; then \
        go mod download -x ; \
    fi

RUN --mount=type=cache,target=/go/pkg/mod/ \
    --mount=type=bind,target=. \
    if [ "$TARGETARCH" = "arm64" ]; then \
        CC=aarch64-linux-gnu-gcc \
        go build -ldflags '-w -s -X "main.Version=${VERSION}"' -o /bin/myencrypt ./cmd/myencrypt \
    elif [ "$TARGETARCH" = "amd64" ]; then \
        go build -ldflags '-w -s -X "main.Version=${VERSION}"' -o /bin/myencrypt ./cmd/myencrypt \
    fi

FROM --platform=$BUILDPLATFORM gcr.io/distroless/static-debian12 AS final

ENV MYENCRYPT_EXPOSE_PORT=14000 \
    MYENCRYPT_PROJECT_NAME=myencrypt \
    MYENCRYPT_INDIVIDUAL_CERT_TTL=168h \
    MYENCRYPT_CA_CERT_TTL=19200h \
    MYENCRYPT_ALLOWED_DOMAINS=localhost,*.localhost,*.test,*.example,*.invalid,app.localhost \
    MYENCRYPT_CERT_STORE_PATH=/data \
    MYENCRYPT_DATABASE_PATH=/data/myencrypt.db \
    MYENCRYPT_LOG_LEVEL=info

COPY --from=build /bin/myencrypt /bin/

EXPOSE 80

ENTRYPOINT [ "/bin/myencrypt" ]
CMD ["run"]
