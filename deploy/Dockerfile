# syntax=docker/dockerfile:1
FROM golang:1.25-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=secret,id=proxy_ca if [ -f /run/secrets/proxy_ca ]; then SSL_CERT_FILE=/run/secrets/proxy_ca go mod download; else go mod download; fi
COPY . .
RUN CGO_ENABLED=0 go build -o /out/control-plane ./services/control-plane/cmd/control-plane && CGO_ENABLED=0 go build -o /out/relay ./services/relay/cmd/relay && CGO_ENABLED=0 go build -o /out/dev-init ./tools/dev-init && CGO_ENABLED=0 go build -o /out/echo ./tools/echo/cmd/echo && CGO_ENABLED=0 go build -o /out/dev-client ./tools/dev-client
FROM debian:bookworm-slim
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/ /app/
WORKDIR /app
USER 10001:10001
