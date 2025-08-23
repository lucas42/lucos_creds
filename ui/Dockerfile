FROM node:24-alpine

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

## Run the build step and then delete everything which only gets used for the build
RUN npm run build

RUN rm -rf node_modules client service-worker webpack*
RUN npm install --omit=dev

ENV NODE_ENV production
EXPOSE $PORT

CMD [ "npm", "start" ]