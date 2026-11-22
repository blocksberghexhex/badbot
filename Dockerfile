# syntax=docker/dockerfile:1

# --- Bauen ---------------------------------------------------------------
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Bewusst nicht VERSION: Build-Umgebungen reichen Variablen dieses Namens
# gern ungefragt durch.
ARG BADBOT_COLLECTOR_VERSION=entwicklung
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags="-s -w -X main.Version=${BADBOT_COLLECTOR_VERSION}" \
      -o /out/badbot-collector ./cmd/badbot-collector

# --- Laufen --------------------------------------------------------------
# nft wird fuer die Sperren gebraucht; sonst nichts.
FROM alpine:3.22
RUN apk add --no-cache nftables
COPY --from=build /out/badbot-collector /usr/local/bin/badbot-collector
VOLUME /var/lib/badbot-collector
ENTRYPOINT ["/usr/local/bin/badbot-collector"]
