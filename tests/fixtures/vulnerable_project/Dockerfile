FROM node:18-alpine
WORKDIR /app
COPY . .
ENV DATABASE_PASSWORD=superSecretProd123
ARG API_SECRET_KEY=r8v2Kq9Lm3Xn7Bp4Ws6Ht1Jc5Fd0Gn
RUN npm install
CMD ["npm", "start"]
