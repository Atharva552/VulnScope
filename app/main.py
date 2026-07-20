from fastapi import FastAPI

app = FastAPI(
    title="Basic VAPT Scanner",
    description="A web-based Vulnerability Assessment Tool",
    version="1.0.0"
)


@app.get("/")
def home():
    return {
        "project": "Basic VAPT Scanner",
        "status": "Running Successfully"
    }