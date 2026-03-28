import os
from dotenv import load_dotenv

load_dotenv()

DAYTONA_API_KEY = os.getenv("DAYTONA_API_KEY")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

MAX_WORKERS = int(os.getenv("MAX_WORKERS", "5"))   # stay well under 30GB
