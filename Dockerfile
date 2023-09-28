FROM node:20

WORKDIR  /app

#Install app dependencies
COPY package*.json ./
RUN npm install

#Bundle application code
COPY . .

#Run Application
CMD [ "npm", "run", "start:dev"]