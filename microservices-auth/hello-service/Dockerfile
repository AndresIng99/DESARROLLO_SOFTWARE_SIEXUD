FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
RUN npm config set strict-ssl false && npm install --only=production

COPY . .

RUN addgroup -g 1001 -S nodejs
RUN adduser -S nodejs -u 1001
RUN chown -R nodejs:nodejs /app
USER nodejs

EXPOSE 3010

CMD ["npm", "start"]