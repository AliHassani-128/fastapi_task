from fastapi import FastAPI, Depends, HTTPException


app = FastAPI()
db = models.db


@app.get('/')
def home():
    return {'Homepage': 'hello world'}
