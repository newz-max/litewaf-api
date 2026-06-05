ARG GO_BUILDER_IMAGE=golang:1.24-bookworm
ARG API_RUNTIME_IMAGE=debian:12-slim
FROM ${GO_BUILDER_IMAGE} AS builder

WORKDIR /src
ENV GOPROXY=https://goproxy.cn,direct

COPY go.mod ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/litewaf-api ./cmd/litewaf-api

FROM ${API_RUNTIME_IMAGE}

RUN groupadd --system litewaf \
    && useradd --system --gid litewaf --home-dir /app --shell /usr/sbin/nologin litewaf

WORKDIR /app
COPY --from=builder /out/litewaf-api /app/litewaf-api

USER litewaf
EXPOSE 8080

ENV HTTP_ADDR=:8080

CMD ["/app/litewaf-api"]
