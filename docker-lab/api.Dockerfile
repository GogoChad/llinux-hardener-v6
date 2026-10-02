FROM python:3.12-slim
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir -e .
CMD ["linux-hardener-api"]
