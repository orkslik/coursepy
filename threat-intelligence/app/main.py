from fastapi import FastAPI

app = FastAPI(title="Threat Intelligence")


@app.get("/health")
def health():
    return {"status": "threat-intelligence alive"}


@app.post("/check")
def check_signature(data: dict):
    return {
        "known_threat": False,
        "confidence": 0.1
    }
