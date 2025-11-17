import os
import requests
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def test_projectdiscovery_connection():
    """Test ProjectDiscovery ASM API connection using credentials from .env file"""
    api_key = os.getenv("PROJECTDISCOVERY_API_KEY")
    
    if not api_key:
        print("Error: ProjectDiscovery API key not found in .env file")
        return False
    
    # Test endpoint for ASM API using cloud domain
    url = "https://cloud.projectdiscovery.io/api/v1/status"
    headers = {
        "X-API-Key": api_key,
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            print("ProjectDiscovery ASM API Connection Successful!")
            print(f"Status Code: {response.status_code}")
            print(f"Response: {response.text[:200]}...")  # Show first 200 chars of response
            return True
        else:
            print(f"ProjectDiscovery ASM API Connection Failed with status code: {response.status_code}")
            print(f"Response: {response.text}")
            return False
            
    except Exception as e:
        print(f"Error connecting to ProjectDiscovery ASM API: {e}")
        return False

def test_alternative_endpoint():
    """Try an alternative endpoint if the first one fails"""
    api_key = os.getenv("PROJECTDISCOVERY_API_KEY")
    
    # Alternative endpoint
    url = "https://cloud.projectdiscovery.io/api/v1/user/info"
    headers = {
        "X-API-Key": api_key,
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.get(url, headers=headers)
        print(f"\nTrying alternative endpoint: {url}")
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.text[:200]}...")  # Show first 200 chars of response
        return response.status_code == 200
    except Exception as e:
        print(f"Error with alternative endpoint: {e}")
        return False

if __name__ == "__main__":
    print("Testing ProjectDiscovery ASM API Connection...")
    success = test_projectdiscovery_connection()
    
    if not success:
        print("\nTrying alternative endpoint...")
        test_alternative_endpoint()