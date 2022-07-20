from fastapi import FastAPI, Request
from datetime import datetime
import uuid
import json

app = FastAPI()


@app.get("/")
async def read_root(request: Request):
    filename = str(uuid.uuid4())

    with open(f'output/{filename}.txt','w') as f:
        f.write(f"{request.headers.get('X-FP-IP')}:{request.headers.get('X-FP-Port')}\n")
        f.write(f"{request.headers.get('user-agent')}\n")
        for key,value in request.headers.items():
            f.write(f"{key}: {value}\n")
    
    return {"ts": datetime.now(), "status": 200, "msg": filename}