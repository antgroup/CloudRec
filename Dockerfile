FROM maven:3.8-openjdk-17-slim AS server_builder
WORKDIR /build
COPY . .
RUN mvn --quiet package

FROM golang:bullseye AS collector_builder
WORKDIR /build
COPY /collector/. .
RUN CGO_ENABLED=0 GOARCH=amd64 GOOS=linux go build -o collectors .

FROM ibm-semeru-runtimes:open-17.0.15_6-jre
WORKDIR /cloudrec
ENV PARAMS=""
ENV TZ=PRC
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone
RUN curl -L -o ./opa https://github.com/open-policy-agent/opa/releases/download/v1.4.2/opa_linux_amd64_static
RUN mkdir -p /cloudrec/logs/

COPY --from=server_builder /build/app/bootstrap/target/cloudrec.jar .
COPY --from=collector_builder /build/collectors .
COPY --from=collector_builder /build/config.yaml .
COPY rules ./rules

COPY entrypoint.sh /etc/entrypoint.sh
RUN chmod +x /etc/entrypoint.sh
ENTRYPOINT ["/etc/entrypoint.sh"]
