from fastapi import FastAPI, Request
from datetime import datetime
import uuid
import json

app = FastAPI()


@app.get("/")
async def read_root(request: Request):
    filename = str(uuid.uuid4())

    with open(f'output/{filename}.txt','w') as f:
        f.write(f"{request.client.host}:{request.client.port}\n")
        f.write(f"{request.headers.get('user-agent')}\n")
        f.write(json.dumps(request.headers.keys()) + '\n')
    
    return {"ts": datetime.now(), "status": 200, "msg": "OK"}