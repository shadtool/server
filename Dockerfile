FROM node:22-alpine

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --production

COPY server.js stage-server.js ./

# Certs and logs are mounted as volumes
RUN mkdir -p certs logs

EXPOSE 8443 443 8444

# Default to the main C2 server; override with stage-server.js if needed
CMD ["node", "server.js"]
