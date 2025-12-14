from fastapi import FastAPI

app = FastAPI(title="Monitoring Service")


@app.get("/health")
def health():
    return {"status": "monitoring-service alive"}


@app.post("/event")
def collect_event(event: dict):
    return {"status": "event received"}
