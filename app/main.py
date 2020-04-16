from fastapi import FastAPI
from pymongo import MongoClient 
from .user import router as api_router
from .database import connect_to_mongo, close_mongo_connection
from motor.motor_asyncio import AsyncIOMotorClient



app = FastAPI()

app.add_event_handler("startup", connect_to_mongo)
app.add_event_handler("shutdown", close_mongo_connection)

app.include_router(api_router,prefix='/user')
