FROM python:3.9-alpine
LABEL MAINTAINER="Joe Mama <john.doe@example.com>"
ENV PS1="\[\e[0;33m\]|> scapy_endpoint <| \[\e[1;35m\]\W\[\e[0m\] \[\e[0m\]# "

WORKDIR /src
COPY . /src
RUN pip install --no-cache-dir -r requirements.txt \
    && python setup.py install
WORKDIR /
ENTRYPOINT ["scapy_endpoint"]
