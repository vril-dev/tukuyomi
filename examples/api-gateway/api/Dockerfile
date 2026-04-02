FROM node:22-alpine

WORKDIR /app

COPY package.json ./
RUN npm install --no-audit --no-fund

COPY index.js ./

EXPOSE 8080
CMD ["node", "index.js"]
