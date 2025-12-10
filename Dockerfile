FROM alpine:3.21
ARG TARGETARCH
ARG VERSION
RUN apk upgrade

COPY speedupdate-${VERSION}_linux_$TARGETARCH/speedupdate-${VERSION}_linux_$TARGETARCH /usr/local/bin/speedupdate
COPY speedupdate-${VERSION}_linux_$TARGETARCH/speedupdateserver-${VERSION}_linux_$TARGETARCH /usr/local/bin/speedupdateserver

RUN chmod +x /usr/local/bin/speedupdateserver
RUN chmod +x /usr/local/bin/speedupdate

WORKDIR /opt

COPY pkey /etc/speedupdate/pkey

EXPOSE 8012

CMD ["speedupdateserver"] 
