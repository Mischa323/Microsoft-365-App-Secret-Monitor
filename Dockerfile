FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY . .

ARG GIT_SHA=unknown
ENV APP_VERSION=$GIT_SHA

# Runtime data lives in a mounted volume at /data
ENV DATA_DIR=/data
ENV PORT=3000

EXPOSE 3000

CMD ["node", "server.js"]
