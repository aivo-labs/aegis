FROM alpine:3.20

RUN apk add --no-cache \
    nginx \
    php83 \
    php83-fpm \
    php83-json \
    php83-ctype \
    php83-curl \
    php83-mbstring \
    php83-openssl \
    php83-session \
    nodejs \
    bind-tools \
    curl \
    bash

RUN mkdir -p /run/nginx /var/www/html /app/node

COPY nginx.conf /etc/nginx/http.d/default.conf
COPY www/ /var/www/html/
COPY node-service.mjs /app/node/node-service.mjs
COPY entrypoint.sh /entrypoint.sh

RUN sed -i 's/listen = 127.0.0.1:9000/listen = 127.0.0.1:9000/' /etc/php83/php-fpm.d/www.conf && \
    sed -i 's/;clear_env = no/clear_env = no/' /etc/php83/php-fpm.d/www.conf && \
    sed -i 's/pm.max_children = 5/pm.max_children = 20/' /etc/php83/php-fpm.d/www.conf && \
    chmod +x /entrypoint.sh

EXPOSE 80

CMD ["/entrypoint.sh"]
