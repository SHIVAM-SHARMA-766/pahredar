FROM node:22-alpine AS build
WORKDIR /app
# npm 10's resolver crashes on Vite 8's optional peer dependencies; npm 11 does not.
RUN npm install -g npm@11
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
RUN npm run build

FROM nginx:1.29-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
