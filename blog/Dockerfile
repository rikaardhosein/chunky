FROM ubuntu:20.04


RUN apt update && apt install -y python3 python3-pip

RUN mkdir /app
COPY src /app

WORKDIR /app

RUN pip install -r requirements.txt
ENTRYPOINT ["gunicorn", "-w", "8", "-b", "0.0.0.0:8002", "app:app"]
