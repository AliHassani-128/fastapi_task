from pydantic import BaseModel
from pymongo import MongoClient
from bson import ObjectId


client = MongoClient()
db = client['my_task_db']


class User(BaseModel):
    _id : ObjectId
    username : str
    password : str

    class Config:
        schema_extra = {
            "example": {
                "username": "Username",
                "password":"some password",
            }
        }