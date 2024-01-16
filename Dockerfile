FROM golang:1.21 AS builder

WORKDIR /go/src/lucos_creds

COPY go.* .
RUN go mod download

COPY src .
RUN go build

FROM scratch

COPY --from=builder /go/src/lucos_creds/lucos_creds .

CMD ["/lucos_creds"]