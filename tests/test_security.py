from app.security import hash_password,verify_password
def test_hash():
 h=hash_password('abc123');assert verify_password('abc123',h);assert not verify_password('wrong',h)
