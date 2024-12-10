# syntax=docker/dockerfile:1
FROM ubuntu:22.04

# Then Quiche Dockerfile changes the directory and runs from there
WORKDIR /app

COPY target/debug/quiche-client /app/quiche-client
COPY client.sh /app/client.sh

RUN mkdir /app/received_files
RUN mkdir /app/logs
RUN chmod +x /app/quiche-client
RUN chmod +x /app/client.sh

ENTRYPOINT ["./client.sh"]
CMD ["quiche-server"]
