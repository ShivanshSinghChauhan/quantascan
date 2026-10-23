# Multi-stage production build for QuantaScan
FROM node:22-alpine AS builder

WORKDIR /app
COPY package*.json tsconfig.json ./
RUN npm ci

COPY src/ ./src/
RUN npm run build

# Production runner stage
FROM node:22-alpine AS runner

WORKDIR /app
ENV NODE_ENV=production
ENV PORT=8080

COPY package*.json ./
RUN npm ci --omit=dev

COPY --from=builder /app/dist ./dist
COPY action.yml README.md ./

EXPOSE 8080

CMD ["node", "dist/bin/pqc-scan.js", "--serve", "--port", "8080"]
