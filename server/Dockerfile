FROM golang:1.26 AS builder

WORKDIR /go/src/lucos_creds

COPY go.* .
RUN go mod download

COPY src .
RUN go build

RUN apt-get update && apt-get install -y netcat-openbsd && rm -rf /var/lib/apt/lists/*

ENV PORT=2202
EXPOSE $PORT

CMD ["./lucos_creds"]