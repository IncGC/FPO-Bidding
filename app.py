from fastapi.middleware.cors import CORSMiddleware
from supertokens_fastapi import get_cors_allowed_headers
import uvicorn
from fastapi import FastAPI, File, UploadFile, Request
# import soundfile as sf
import shutil
import json
from main import *

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["Content-Type"] + get_cors_allowed_headers(),
)


"""
this function is main dasboard api
"""
@app.post("/dasboard")
async def create_item2(request: Request):
    b_json = await request.body()
    dt = json.loads(b_json)
    return main(dt)




if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0",port=5001,debug="True")