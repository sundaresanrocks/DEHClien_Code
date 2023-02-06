FROM ubuntu:20.04

LABEL Description="This image is used to invoke DEHClient Enabler api"

MAINTAINER Sundaresan "sundaresan.venkatesan@wit.ie"

RUN apt-get update && apt-get install -y software-properties-common && add-apt-repository ppa:deadsnakes/ppa && \
    apt-get update && apt-get install -y python3.8 python3.8-dev python3-pip

RUN ln -sfn /usr/bin/python3.8 /usr/bin/python3 && ln -sfn /usr/bin/python3 /usr/bin/python && ln -sfn /usr/bin/pip3 /usr/bin/pip

RUN mkdir -p /app/

RUN mkdir -p /app/DEHClientEnabler/

RUN mkdir -p /app/DEHClientEnabler/resource_monitor/

# Copy requirements & DEH Client code from the relative path
COPY ./requirements.txt /app/DEHClientEnabler/requirements.txt

COPY ./resource_monitor/ /app/DEHClientEnabler/resource_monitor/

RUN find /app/DEHClientEnabler/resource_monitor/

WORKDIR /app/DEHClientEnabler/

ENV PYTHONPATH="$PYTHONPATH:/app/DEHClientEnabler/resource_monitor/"

RUN pip3 install -r requirements.txt

ENTRYPOINT ["python3", "/app/DEHClientEnabler/resource_monitor/main.py"]