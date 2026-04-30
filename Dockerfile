# syntax=docker/dockerfile:1

FROM golang:1.26-alpine AS build

ARG VERSION=0.1.0-dev
ARG COMMIT=unknown
ARG DATE=unknown

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags="-s -w -X github.com/faultline-go/faultline/internal/version.Version=${VERSION} -X github.com/faultline-go/faultline/internal/version.Commit=${COMMIT} -X github.com/faultline-go/faultline/internal/version.BuildDate=${DATE}" \
    -o /out/faultline ./cmd/faultline

FROM golang:1.26-alpine

ARG VERSION=0.1.0-dev

LABEL org.opencontainers.image.source="https://github.com/faultline-go/faultline" \
      org.opencontainers.image.description="Faultline structural risk analysis CLI for Go codebases" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}"

RUN apk add --no-cache ca-certificates git
COPY --from=build /out/faultline /usr/local/bin/faultline
COPY faultline.example.yaml /usr/local/share/faultline/faultline.example.yaml
COPY README.md LICENSE /usr/local/share/faultline/

WORKDIR /workspace
ENTRYPOINT ["faultline"]
CMD ["version"]
