# syntax=docker/dockerfile:1
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y iproute2

# Then Quiche Dockerfile changes the directory and runs from there
WORKDIR /app

EXPOSE 1234/udp
EXPOSE 4433/udp

COPY target/debug/quiche-server /app/quiche-server
COPY apps/src/bin/cert.crt /app/apps/src/bin/cert.crt
COPY apps/src/bin/cert.key /app/apps/src/bin/cert.key
COPY server.sh /app/server.sh
COPY send_files/policies /app/policies

RUN mkdir /app/logs
RUN chmod +x /app/quiche-server
RUN chmod +x /app/server.sh

ENTRYPOINT ["./server.sh"]
CMD ["default"]
