FROM nginx:alpine
RUN apk add --no-cache openssl
COPY conf/ /opt/nginx-src/conf/
COPY content/ /opt/nginx-src/content/
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 80 443
ENTRYPOINT ["/entrypoint.sh"]
