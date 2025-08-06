# syntax=docker/dockerfile:1

ARG GO_VERSION=1.24.5

FROM --platform=${BUILDPLATFORM} golang:${GO_VERSION} AS build
WORKDIR /src

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=latest

ENV CGO_ENABLED=1

RUN --mount=type=cache,target=/go/pkg/mod/ \
    --mount=type=bind,source=go.sum,target=go.sum \
    --mount=type=bind,source=go.mod,target=go.mod \
    go mod download -x ;

RUN --mount=type=cache,target=/go/pkg/mod/ \
    --mount=type=bind,target=. \
    go build -ldflags '-w -s -X "main.Version=${VERSION}"' -o /bin/myencrypt ./cmd/myencrypt

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
