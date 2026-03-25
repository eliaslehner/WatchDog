FROM python:3.11-slim

ENV DATABASE_URL=postgres://admin:SuperSecret123!@db.prod.internal:5432/maindb
ENV SECRET_KEY=django-insecure-k8s!_p3rf3ct_s3cr3t_k3y_2026
ARG GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789

RUN pip install -r requirements.txt

COPY . /app
COPY .env /app/.env

USER root
EXPOSE 8000

CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
