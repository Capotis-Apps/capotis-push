FROM node:20-alpine
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund
COPY server.js ./
COPY public ./public
# Carpeta de datos (usuario, llave .p8, dispositivos). Se guarda en un volumen.
RUN mkdir -p /data && chown -R node:node /data /app
ENV NODE_ENV=production PORT=7391 DATA_DIR=/data
VOLUME ["/data"]
EXPOSE 7391
USER node
CMD ["node", "server.js"]
