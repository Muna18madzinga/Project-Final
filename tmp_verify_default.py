from main import app

with app.test_client() as client:
    login_resp = client.post('/auth/login', json={'username': 'Theo_Madzinga', 'password': 'Theo@1172025'})
    print(login_resp.status_code)
    print(login_resp.json)
