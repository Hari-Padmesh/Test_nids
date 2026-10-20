import os

from fastapi import FastAPI
from netguard import NetGuard
from netguard.integrations.fastapi import setup_netguard

app = FastAPI(title="My API")

guard = NetGuard(
    project_id="my-api",
    auth_username=os.environ["NETGUARD_AUTH_USERNAME"],
    auth_password=os.environ["NETGUARD_AUTH_PASSWORD"],
)

setup_netguard(app, guard)


@app.get("/")
async def home():
    return {"message": "My API is running"}


@app.get("/items/{item_id}")
async def get_item(item_id: int):
    return {"item_id": item_id}