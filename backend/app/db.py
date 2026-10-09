from __future__ import annotations

from pymongo import MongoClient

from app.settings import settings


client = MongoClient(settings.mongo_uri)
db = client.get_default_database()


def col(name: str):
    return db[name]

