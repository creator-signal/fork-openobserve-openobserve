FROM golang:1.26.9-alpine3.24@sha256:3082400e369fa24d5fc60bca20edab3f6d604e0c5a690ec66b295eff4dd87ade AS build
WORKDIR /src
ENV CGO_ENABLED=0
COPY collector/ ./collector/
RUN mkdir -p /src/.tmp/7-openbao-memory && \
    go run go.opentelemetry.io/collector/cmd/builder@v0.157.0 --config collector/builder-config.yaml
RUN cd collector/openbaoauthextension && go build -trimpath -o /src/.tmp/7-openbao-memory/collector-healthcheck ./cmd/healthcheck

FROM scratch
ARG SOURCE_REVISION
LABEL org.opencontainers.image.source="https://github.com/creator-signal/fork-openobserve-openobserve" \
      org.opencontainers.image.revision="${SOURCE_REVISION}" \
      org.opencontainers.image.title="Creator Signal OpenBao OTLP collector"
COPY --from=build /src/.tmp/7-openbao-memory/collector-distribution/otelcol-contrib /otelcol-contrib
COPY --from=build /src/.tmp/7-openbao-memory/collector-healthcheck /collector-healthcheck
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
USER 10001:10001
HEALTHCHECK --interval=30s --timeout=3s --start-period=30s --retries=3 CMD ["/collector-healthcheck"]
ENTRYPOINT ["/otelcol-contrib", "--feature-gates=+extension.healthcheck.useComponentStatus"]
