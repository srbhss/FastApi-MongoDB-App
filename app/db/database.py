from motor.motor_asyncio import AsyncIOMotorClient

myclient: AsyncIOMotorClient = None

async def connect_to_mongo():
    MONGODB_URL = "mongodb://localhost:27017/"
    myclient = AsyncIOMotorClient(str(MONGODB_URL))
    db = myclient[database_name]
    coll = db[users_collection_name]

async def close_mongo_connection():
    myclient.close()

async def get_database() -> AsyncIOMotorClient:
    return myclient

database_name = "MyMongo"
users_collection_name = "Users"
comments_collection_name = "comments"