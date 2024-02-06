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
Copy the directory from the docker host at /var/lib/docker/volumes/lucos\_creds\_store/\_data/

## Usage

### Setting or updating a credential

`ssh -p 2202 creds.l42.eu ${system}/${environment}/${key}=${value}`

* **system** is the slug of the github repository for system which uses this credential
* **environment** is the name of which environment being used (eg 'production' or 'development')
* **key** is the key of the credential.  Must be unique for the given system/environment combination. Gets normalised to all uppercase
* **value** is the value of the credential.

Note: only **value** gets encrypted at rest.  *DO NOT* place any sensitive data in the other fields

### Populate an envfile for local development

`scp -P 2202 "creds.l42.eu:${PWD##*/}/development/.env" .`

(Worth aliasing in .bashrc for convenience)


### Populate as part of a deployment script to production

`scp -s -P 2202 -o BatchMode=yes $DEPLOY_USERNAME@creds.l42.eu:$CIRCLE_PROJECT_REPONAME/production/.env .`

* **DEPLOY_USERNAME** Set in personal circleci context `docker` (SSH key must be set up matching this user)
* **CIRCLE_PROJECT_REPONAME** Set by circleci - the name of the repositoriy being deployed


## References

* [Draft spec of SFTP that most stuff seems to support these days](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02)
* [Golang docs for built-in SSH package](https://pkg.go.dev/golang.org/x/crypto/ssh)