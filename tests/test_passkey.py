from passkey.service import PasskeyService

def test_passkey():
    s = PasskeyService()
    res = s.create_registration_challenge("alex")
    assert "challenge" in res
