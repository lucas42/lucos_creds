# Vocabulary stage: canonical scope vocabulary from lucos_auth_scopes.
# Named stage so Dependabot can track the tag + digest.
FROM lucas42/lucos_auth_scopes:1.2.0@sha256:c4e9b6087166f65836cf4859774303f3482796a353a545b91e1e138f4eeb343c AS scopes

FROM golang:1.26 AS builder
ARG VERSION
ENV VERSION=$VERSION

WORKDIR /go/src/lucos_creds

COPY go.* .
RUN go mod download

COPY src .
# Inject canonical scopes.yaml from the vocabulary stage (above).
# The committed server/src/scopes.yaml is overwritten here so Docker builds always
# use the pinned-version vocabulary, not a potentially stale committed copy.
COPY --from=scopes /scopes.yaml ./
RUN go build

RUN apt-get update && apt-get install -y netcat-openbsd && rm -rf /var/lib/apt/lists/*

ENV PORT=2202
EXPOSE $PORT

CMD ["./lucos_creds"]