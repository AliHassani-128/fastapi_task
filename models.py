from typing import Optional

from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel,Field
from pymongo import MongoClient
from bson import ObjectId




uri = 'mongodb://127.0.0.1:27017'
client = AsyncIOMotorClient(uri)
db = client['my_task_db']


# client = MongoClient()
# db = client['my_task_db']


class User(BaseModel):
    _id : ObjectId
    username : str
    password : str
    national_code:str=Field(title='National code',min_length=10,max_length=10,)

    class Config:
        schema_extra = {
            "example": {
                "username": "Username",
                "password":"some password",
                "national_code":"123456789",
            }
        }


class Token(BaseModel):
    access_token:str
    token_type:str


class TokenData(BaseModel):
    username: Optional[str] = None


class Text(BaseModel):
    _id = ObjectId
    text:str
    writer:User
