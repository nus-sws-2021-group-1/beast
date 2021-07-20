FROM python:3

WORKDIR /usr/src/app

RUN apt-get update && apt-get install -y libpcap0.8
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY scripts/* ./
COPY certs/server* ./
