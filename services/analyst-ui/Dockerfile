# Build
FROM node:20-slim AS builder
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev=false
COPY . .
RUN npm run build

# Run
FROM node:20-slim
WORKDIR /app
ENV PORT=8080
COPY --from=builder /app .
EXPOSE 8080
CMD ["npm","run","start"]
