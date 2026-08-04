FROM node:22-alpine AS build
WORKDIR /src
COPY web/package.json ./
RUN npm install
COPY web/ ./
RUN npm run build

FROM nginx:alpine
COPY web/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /src/dist /usr/share/nginx/html
EXPOSE 80
