# lucos_creds
A credential manager for lucos systems


## Dependencies

* docker
* docker-compose

## Build-time Dependencies

* [Golang](https://golang.org/)

## Running
`docker compose up --build`

## Testing
Run `go test ./src`

[![CircleCI](https://circleci.com/gh/lucas42/lucos_creds.svg?style=shield)](https://circleci.com/gh/lucas42/lucos_creds)

For code coverage, run tests with:
`go test ./src -coverprofile=coverage.out`
Then, to view coverage report in browser, run:
`go tool cover -html=coverage.out`

## Backing Up
Copy the directory from the docker host at /var/lib/docker/volumes/lucos_creds_store/_data/