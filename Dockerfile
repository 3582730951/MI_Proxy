# syntax=docker/dockerfile:1

FROM golang:1.18-bullseye@sha256:2cf761b45e5e3f150e332e60275cd092fb50b05fff4feec0a2856a09f9fe6b2b AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go test ./...
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/control-plane ./cmd/control-plane
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/agent ./cmd/agent

FROM ubuntu:22.04@sha256:4f838adc7181d9039ac795a7d0aba05a9bd9ecd480d294483169c5def983b64d
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/control-plane /usr/local/bin/control-plane
COPY --from=build /out/agent /usr/local/bin/sing-box-next-agent
COPY apps/web /usr/share/sing-box-next-panel/web
RUN useradd --system --uid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin singboxnext
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/control-plane"]
