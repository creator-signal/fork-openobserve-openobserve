FROM golang:1.26.9-alpine3.24@sha256:3082400e369fa24d5fc60bca20edab3f6d604e0c5a690ec66b295eff4dd87ade AS build
WORKDIR /src
ENV CGO_ENABLED=0
COPY collector/ ./collector/
RUN go run go.opentelemetry.io/collector/cmd/builder@v0.157.0 --config collector/builder-config.yaml

FROM scratch
ARG SOURCE_REVISION
LABEL org.opencontainers.image.source="https://github.com/creator-signal/fork-openobserve-openobserve" \
      org.opencontainers.image.revision="${SOURCE_REVISION}" \
      org.opencontainers.image.title="Creator Signal OpenBao OTLP collector"
COPY --from=build /src/.tmp/7-openbao-memory/collector-distribution/otelcol-contrib /otelcol-contrib
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
USER 10001:10001
ENTRYPOINT ["/otelcol-contrib"]
