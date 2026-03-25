import os

# Production configuration
DATABASE_URL = "postgres://admin:SuperSecret123!@db.prod.internal:5432/maindb"
SECRET_KEY = "django-insecure-k8s!_p3rf3ct_s3cr3t_k3y_2026"
DEBUG = True

CORS_ALLOWED_ORIGINS = ["*"]

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

GOOGLE_API_KEY = "AIzaSyA1234567890abcdefghijklmnopqrstuv"

SLACK_BOT_TOKEN = "xoxb-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx"
