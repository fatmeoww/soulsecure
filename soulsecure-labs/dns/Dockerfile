FROM alpine:3.20
RUN apk add --no-cache coredns
COPY Corefile.tmpl zone-lab1.tmpl zone-lab2.tmpl /opt/dns-src/
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 53/udp 53/tcp
ENTRYPOINT ["/entrypoint.sh"]
