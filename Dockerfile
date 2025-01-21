FROM python:3.11-alpine

WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir gunicorn
EXPOSE 5000

ENV FLASK_ENV=production
ENV FLASK_APP=app.py

CMD ["gunicorn", "--workers", "1", "--bind", "0.0.0.0:5000", "--log-level=info", "--access-logfile=-", "app:app"]