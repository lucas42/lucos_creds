# Vocabulary stage: canonical scope vocabulary from lucos_auth_scopes.
# Named stage so Dependabot can track the tag + digest.
FROM lucas42/lucos_auth_scopes:1.3.0@sha256:55cf77f4597c59b65bd22c0f49a7ca020627412dfa02d954f694027188f169d3 AS scopes

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