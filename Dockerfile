FROM python:3.12.2-slim

COPY ./server.py /code/
COPY ./scanner.py /code/
COPY ./requirements /code/

WORKDIR /code

RUN apt update && \
    apt install -y iputils-ping && \
    pip3 install -r requirements

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "80"]