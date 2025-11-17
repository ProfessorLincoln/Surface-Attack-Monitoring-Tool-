import os
from dotenv import load_dotenv
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure

# Load environment variables
load_dotenv()

def test_mongodb_connection():
    """Test MongoDB connection using credentials from .env file"""
    mongo_uri = os.getenv("MONGO_URI")
    
    # Check if MONGO_URI contains placeholder
    if "<db_password>" in mongo_uri:
        print("Error: MongoDB URI contains placeholder <db_password>. Please replace with actual password.")
        return False
    
    try:
        # Create a MongoDB client
        client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
        
        # Force a connection to verify it works
        client.admin.command('ping')
        
        # Get database names to verify access
        db_names = client.list_database_names()
        
        print("MongoDB Connection Successful!")
        print(f"Available databases: {', '.join(db_names)}")
        return True
    
    except ConnectionFailure as e:
        print(f"MongoDB Connection Failed: {e}")
        return False
    except Exception as e:
        print(f"Error connecting to MongoDB: {e}")
        return False

if __name__ == "__main__":
    print("Testing MongoDB Connection...")
    test_mongodb_connection()