FROM python:3.11-alpine

WORKDIR /app
COPY app.py /app
RUN pip install --no-cache-dir flask gunicorn
EXPOSE 5000

ENV FLASK_ENV=production
ENV FLASK_APP=app.py
ENV TOKEN="default"

CMD ["gunicorn", "--workers", "1", "--bind", "0.0.0.0:5000", "app:app"]