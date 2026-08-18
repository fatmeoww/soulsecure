FROM alpine:3.20
RUN apk add --no-cache socat
COPY banner.sh /banner.sh
RUN chmod +x /banner.sh
EXPOSE 25
CMD ["socat", "-T5", "TCP-LISTEN:25,reuseaddr,fork", "SYSTEM:/banner.sh"]
