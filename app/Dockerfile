FROM python:3.13-slim

WORKDIR /app

COPY ./app/requirements.txt ./app/app.py ./

RUN apt-get update && \
    apt-get -y upgrade && \
    apt-get install -y ffmpeg && \
    pip install -r requirements.txt

EXPOSE 80

COPY . /app

ENTRYPOINT ["streamlit", "run", "app.py", "--server.port", "80"]