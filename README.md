# AI-Powered Digital Trust and Cyber Threat Detection — AI Engine

## Features
1. Message phishing detection using TF-IDF + Logistic Regression.
2. URL risk detection using extracted lexical features and explainable rules.
3. Digital Trust Score from 0 to 100, with Low / Medium / High Risk.
4. Separate importable Python modules for integration with a frontend.

## Setup
Use Python 3.10+.

```bash
python -m venv venv
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

pip install -r requirements.txt
python -m ai_engine.test_samples
```

## Import from another Python file
```python
from ai_engine.message_detector import detect_message
from ai_engine.url_detector import detect_url
from ai_engine.trust_score import calculate_trust_score

message_result = detect_message("URGENT: verify your bank password now")
url_result = detect_url("http://example-login-verify.test")
trust = calculate_trust_score(message_result, url_result)
print(message_result)
print(url_result)
print(trust)
```

## Output meaning
- `label`: Safe or Suspicious.
- `suspicious_probability`: estimated risk from 0.0 to 1.0.
- `confidence`: confidence of the selected class (for the message model, based on its probability output).
- `reasons`: warning indicators that explain the result.
- `trust_score`: 0–100; higher means lower detected risk.

## Integration contract for Member 2
Call `detect_message(message)`, `detect_url(url)`, and
`calculate_trust_score(message_result, url_result)`. Each returns a dictionary
that can be rendered directly in a dashboard.

## Important limitations
This is a hackathon demonstration, not a production security product. The
message model uses a small embedded teaching dataset and can misclassify
unseen messages. The URL detector uses lexical heuristics only: it does not
check domain age, DNS, certificates, threat-intelligence feeds, redirects,
or website content. A "Safe" result is not a guarantee. Do not enter real
passwords, OTPs, or sensitive information during demos. Never automatically
open suspicious links.
