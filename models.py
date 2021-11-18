from typing import Optional

from pydantic import BaseModel
from pymongo import MongoClient
from bson import ObjectId


client = MongoClient()
db = client['my_task_db']


class User(BaseModel):
    _id : ObjectId
    username : str
    password : str
    national_code:str

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
