FROM node:18-alpine

RUN apk add --no-cache freeradius-client

WORKDIR /app

COPY package*.json ./

RUN npm install

COPY . .

EXPOSE 3005

CMD ["node", "index.js"]