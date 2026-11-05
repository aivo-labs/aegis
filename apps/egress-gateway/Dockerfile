FROM node:22-alpine

WORKDIR /app

COPY package.json ./
RUN npm install --omit=dev

COPY . .

EXPOSE 5053/udp
EXPOSE 5053/tcp

CMD ["node", "dist/src/index.js"]
