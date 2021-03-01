FROM python:3-alpine

WORKDIR /usr/src/sentineloneapi/

COPY ./ ./
RUN python setup.py install
