from pymongo import MongoClient
from pymongo.errors import ConnectionFailure

MONGO_URI = "mongodb://admin:password123@100.118.172.97:27017/IntelDB?authSource=IntelDB"
MONGO_DB_NAME = "IntelDB"

try:
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)

    # Force connection
    client.admin.command("ping")

    print("MongoDB connection successful!")
    print(MONGO_URI)
    print(MONGO_DB_NAME)

    # Get DB
    db = client[MONGO_DB_NAME]

    # List collections
    collections = db.list_collection_names()

    print("\nCollections in database:")
    for col in collections:
        print(f"- {col}")

except ConnectionFailure as e:
    print("MongoDB connection failed")
    print(e)