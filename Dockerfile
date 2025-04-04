FROM python:3.12.9-bullseye

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

WORKDIR /app
COPY . /app/

RUN apt-get update \
    && apt-get install -y --no-install-recommends libpq-dev gcc libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --upgrade --no-cache-dir pip \
    && pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir .

CMD ["python", "/app/src/main.py"]