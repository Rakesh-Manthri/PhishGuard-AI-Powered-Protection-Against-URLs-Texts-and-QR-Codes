import requests

BACKEND_URL = "http://127.0.0.1:5000"

def test_register():
    print("Testing Registration...")
    data = {
        "email": "testuser2@example.com",
        "password": "TestPassword123"
    }
    try:
        response = requests.post(f"{BACKEND_URL}/register", json=data)
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.json()}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    test_register()
