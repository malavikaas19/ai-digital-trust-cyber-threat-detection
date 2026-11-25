"""Run this file from the project root: python -m ai_engine.test_samples"""
from ai_engine.message_detector import detect_message
from ai_engine.url_detector import detect_url
from ai_engine.trust_score import calculate_trust_score

SAMPLES = [
    {
        "name": "Normal college message",
        "message": "Hi, the project review is scheduled for 2 PM tomorrow.",
        "url": "https://www.python.org"
    },
    {
        "name": "Suspicious account message",
        "message": "URGENT! Your bank account is suspended. Verify your password and OTP now.",
        "url": "http://192.0.2.10/login/verify-account"
    },
]

def run_tests():
    for sample in SAMPLES:
        print("\\n" + "=" * 55)
        print(sample["name"])
        msg = detect_message(sample["message"])
        url = detect_url(sample["url"])
        trust = calculate_trust_score(msg, url)
        print("Message result:", msg)
        print("URL result:", url)
        print("Digital trust:", trust)

if __name__ == "__main__":
    run_tests()
