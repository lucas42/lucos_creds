FROM golang:1.24.6 AS builder

WORKDIR /go/src/lucos_creds

COPY go.* .
RUN go mod download

COPY src .
RUN go build

ENV PORT=2202
EXPOSE $PORT

CMD ["./lucos_creds"]