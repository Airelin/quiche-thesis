# syntax=docker/dockerfile:1
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y iproute2

# Then Quiche Dockerfile changes the directory and runs from there
WORKDIR /app
RUN mkdir /app/video
RUN mkdir /app/audio
RUN mkdir /app/text
RUN mkdir /app/zip
RUN mkdir /app/image

COPY send_files/bbb_sunflower_1080p_30fps_normal.mp4 /app/video/1.mp4
COPY send_files/extenz-Revolution.wav /app/audio/1.wav
COPY send_files/Textfile.txt /app/text/1.txt
COPY send_files/Zipped-Containers.zip /app/zip/1.zip
COPY send_files/Kangoo.JPG /app/image/1.JPG
COPY send_files/text_features.json /app/text/features.json
COPY send_files/audio_features.json /app/audio/features.json
COPY send_files/image_features.json /app/image/features.json
COPY send_files/video_features.json /app/video/features.json
COPY send_files/zip_features.json /app/zip/features.json

COPY target/debug/quiche-data /app/quiche-data
COPY data.sh /app/data.sh

RUN mkdir /app/logs
RUN chmod +x /app/quiche-data
RUN chmod +x /app/data.sh

ENTRYPOINT ["./data.sh"]
CMD ["video","100mbit", "quiche-server"]
