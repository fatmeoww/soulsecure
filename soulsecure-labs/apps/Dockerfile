FROM python:3.12-alpine
RUN apk add --no-cache bind-tools openssl \
    && pip install --no-cache-dir flask requests
WORKDIR /app
COPY . /app
CMD ["python", "api_app.py"]
