FROM golang:1.25.5-bookworm AS build
WORKDIR /src
COPY apps/api/go.mod apps/api/go.sum ./
RUN go mod download
COPY apps/api/ ./
COPY rules/ /rules/
RUN go test ./...
RUN CGO_ENABLED=1 go build -trimpath -ldflags="-s -w" -o /out/observatory ./cmd/observatory

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/*
RUN useradd --system --uid 10001 --create-home observatory
WORKDIR /app
COPY --from=build /out/observatory /usr/local/bin/observatory
COPY rules/ /app/rules/
RUN mkdir -p /app/data && chown -R observatory:observatory /app
USER observatory
ENV OBSERVATORY_DATA_DIR=/app/data OBSERVATORY_RULE_DIR=/app/rules/public OBSERVATORY_LISTEN=:8080
EXPOSE 8080
ENTRYPOINT ["observatory"]
