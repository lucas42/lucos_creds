# Vocabulary stage: canonical scope vocabulary from lucos_auth_scopes.
# Named stage so Dependabot can track the tag + digest. Pinned to the same
# version as server/Dockerfile's "scopes" stage — keep both pins in sync.
FROM lucas42/lucos_auth_scopes:1.3.6@sha256:ced614dfeebe6406991d91a1e801d6891651a9f53be45f912b9e073d4336c4d8 AS scopes

FROM node:26-alpine
ARG VERSION
ENV VERSION=$VERSION

WORKDIR /usr/src/app
RUN apk add openssh
RUN mkdir ~/.ssh
COPY ssh-config /root/.ssh/config
RUN touch ~/.ssh/id_ed25519 # Gets populated at runtime from an environment variable
RUN chmod 0600 ~/.ssh/id_ed25519

COPY package* ./

RUN npm install

COPY src .
COPY webpack.config.js .
# Inject canonical scopes.yaml from the vocabulary stage (above).
# The committed src/scopes.yaml is overwritten here so Docker builds always
# use the pinned-version vocabulary, not the committed test stub.
COPY --from=scopes /scopes.yaml ./scopes.yaml

## Run the build step and then delete everything which only gets used for the build
RUN npm run build

RUN rm -rf node_modules client service-worker webpack*
RUN npm install --omit=dev

ENV NODE_ENV production

CMD [ "npm", "start" ]