import os
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))
except ImportError:
    pass

ES_HOST     = os.getenv("ES_HOST",     "http://localhost:9200")
ES_USER     = os.getenv("ES_USER",     "elastic")
ES_PASSWORD = os.getenv("ES_PASSWORD", "changeme")
FLASK_URL   = os.getenv("FLASK_URL",   "http://localhost:5000")
FLASK_PORT  = int(os.getenv("FLASK_PORT", "5000"))
