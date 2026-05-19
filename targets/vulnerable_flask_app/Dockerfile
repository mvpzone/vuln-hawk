FROM python:3.13-slim

WORKDIR /app

COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app/

EXPOSE 5000

CMD ["sh", "-c", "python -c 'from db import init_db; init_db()' && flask run --host=0.0.0.0 --port=5000"]
