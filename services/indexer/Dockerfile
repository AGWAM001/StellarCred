FROM node:20-slim

WORKDIR /app

COPY package.json ./
RUN npm install --omit=dev

COPY src ./src

ENV DB_CLIENT=postgres
ENV PORT=4100

EXPOSE 4100

CMD ["node", "src/index.js"]
