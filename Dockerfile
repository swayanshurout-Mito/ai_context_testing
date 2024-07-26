FROM node:20

WORKDIR  /app

#Install app dependencies
COPY package*.json ./
RUN echo "${NPM_AUTH_TOKEN}"
RUN echo "@josys-src:registry=https://npm.pkg.github.com" > .npmrc
RUN echo " //npm.pkg.github.com/:_authToken=${NPM_AUTH_TOKEN}" >> .npmrc
RUN npm install

#Bundle application code
COPY . .

#Run Application
CMD [ "npm", "run", "start:dev"]
