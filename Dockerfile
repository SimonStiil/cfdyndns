FROM scratch

ARG TARGETARCH

WORKDIR /app
COPY ca-certificates.crt /etc/ssl/certs/
COPY cfdyndns-${TARGETARCH} /usr/bin/cfdyndns
ENTRYPOINT ["cfdyndns"]