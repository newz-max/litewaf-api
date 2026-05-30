FROM golang:1.22-bookworm AS builder

WORKDIR /src

COPY go.mod ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/litewaf-api ./cmd/litewaf-api

FROM debian:12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --system litewaf \
    && useradd --system --gid litewaf --home-dir /app --shell /usr/sbin/nologin litewaf

WORKDIR /app
COPY --from=builder /out/litewaf-api /app/litewaf-api

USER litewaf
EXPOSE 8080

ENV HTTP_ADDR=:8080

CMD ["/app/litewaf-api"]
