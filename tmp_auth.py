from main import app

with app.test_client() as client:
    resp = client.post('/auth/login', json={'username':'Theo_Madzinga','password':'Theo@1172025'})
    print(resp.status_code)
    print(resp.json)
