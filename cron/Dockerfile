FROM alpine:3.19

RUN apk add --no-cache curl tzdata bash \
    && cp /usr/share/zoneinfo/UTC /etc/localtime

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

CMD ["/entrypoint.sh"]
