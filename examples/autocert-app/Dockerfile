# syntax=docker/dockerfile:1

ARG GO_VERSION=1.24.5
ARG TARGETARCH

# Install autocert-app command
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION} AS build-autocert-app

WORKDIR /src

RUN --mount=type=cache,target=/go/pkg/mod/ \
    --mount=type=bind,source=go.mod,target=go.mod \
    --mount=type=bind,source=go.sum,target=go.sum \
    go mod download -x

RUN --mount=type=cache,target=/go/pkg/mod/ \
    --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=bind,target=. \
    CGO_ENABLED=0 GOARCH=$TARGETARCH go build -ldflags="-s -w" -trimpath -o /bin/server

# Deploy image
FROM gcr.io/distroless/static-debian12 AS final

COPY --from=build-autocert-app /bin/server /bin/server

EXPOSE 80

ENTRYPOINT [ "/bin/server" ]