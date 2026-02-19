FROM node:18-alpine

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY server.js crypto-utils.js generate-secret.js ./
COPY public/ ./public/

RUN mkdir -p /app/data
VOLUME /app/data

EXPOSE 3000

CMD ["node", "server.js"]
