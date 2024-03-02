FROM python:3.12-slim-bookworm

RUN apt-get update && apt-get install -y sqlite3

COPY backend/requirements.txt .

RUN pip install -r requirements.txt gunicorn

WORKDIR /usr/src

COPY frontend/dist ./dist

COPY backend/tables.sql .
RUN sqlite3 db.sqlite < ./tables.sql
COPY backend/src ./app

CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:8080", "app.app:app"]
