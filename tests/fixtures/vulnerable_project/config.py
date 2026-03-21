# Intentionally vulnerable config for testing
import os

DATABASE_URL = "postgres://admin:supersecretpassword123@db.example.com:5432/myapp"
GOOGLE_API_KEY = "AIzaSyBv2Kq9Lm3Xn7Bp4Ws6Ht1Jc5Fd0Gn8Yr2E"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7VULN0001"
GITHUB_TOKEN = "ghp_R8v2Kq9Lm3Xn7Bp4Ws6Ht1Jc5Fd0Gn8Yr2Ep4"
SLACK_TOKEN = "xoxb-298174562-Kq9Lm3Xn7Bp4"

DEBUG = True
VERBOSE = True

password = "hardcoded_password_value"
secret_key = "my_super_secret_key_value_12345"
