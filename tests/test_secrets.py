from gungnir.vulns.secrets import SecretScanner


def test_detect_aws_key():
    scanner = SecretScanner()
    body = "config: AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
    matches = scanner.scan(body)
    types = [m.type for m in matches]
    assert "aws_access_key_id" in types


def test_detect_github_token():
    scanner = SecretScanner()
    body = "token: ghp_1234567890abcdefghijklmnopqrstuvwxyz"
    matches = scanner.scan(body)
    assert any(m.type == "github_token" for m in matches)


def test_detect_stripe_key():
    scanner = SecretScanner()
    body = "sk_" + "live_51Hqk2yabcd1234567890efghijkl"  # split to avoid secret scanning
    matches = scanner.scan(body)
    assert any(m.type == "stripe_live_key" for m in matches)


def test_detect_jwt():
    scanner = SecretScanner()
    body = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    matches = scanner.scan(body)
    assert any(m.type == "jwt" for m in matches)


def test_detect_private_key():
    scanner = SecretScanner()
    body = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA..."
    matches = scanner.scan(body)
    assert any(m.type == "private_key_rsa" for m in matches)


def test_detect_slack_token():
    scanner = SecretScanner()
    body = "xox" + "b-1234567890-abcdefghijklmnopqrstuvwxyz"  # split to avoid secret scanning
    matches = scanner.scan(body)
    assert any(m.type == "slack_token" for m in matches)


def test_clean_body_no_matches():
    scanner = SecretScanner()
    assert scanner.scan("just some normal text about cats and dogs") == []


def test_has_secret():
    scanner = SecretScanner()
    assert scanner.has_secret("key=AKIAIOSFODNN7EXAMPLE")
    assert not scanner.has_secret("nothing here")


def test_empty_body():
    scanner = SecretScanner()
    assert scanner.scan("") == []


def test_line_number():
    scanner = SecretScanner()
    body = "line one\ntoken AKIAIOSFODNN7EXAMPLE here"
    matches = scanner.scan(body)
    assert matches[0].line == 2


def test_custom_pattern():
    scanner = SecretScanner(extra_patterns=[("custom", r"MYSPECIAL-[0-9]{6}")])
    matches = scanner.scan("found MYSPECIAL-123456 in config")
    assert any(m.type == "custom" for m in matches)


# --- P1 regression: raw-string double-escape fixes ---

def test_detect_s3_bucket_url_literal_dot():
    """aws_s3_bucket_url must match literal dots, not backslash-dot."""
    scanner = SecretScanner()
    body = "cdn https://my-bucket.s3.us-east-1.amazonaws.com/obj"
    assert any(m.type == "aws_s3_bucket_url" for m in scanner.scan(body))


def test_detect_slack_webhook_literal_dot():
    scanner = SecretScanner()
    # Assemble at runtime so the source never contains a contiguous webhook-shaped literal
    # (GitHub push protection flags those even in fixtures).
    host = "hooks." + "slack" + ".com"
    team, channel, token = "T00TEST00", "B00TEST00", "x" * 24
    body = f"https://{host}/services/{team}/{channel}/{token}"
    assert any(m.type == "slack_webhook" for m in scanner.scan(body))


def test_detect_db_connection_with_whitespace_stop():
    """db_connection must stop at whitespace (P1 raw-string whitespace-class fix)."""
    scanner = SecretScanner()
    body = "uri=postgres://user:pass@db.internal:5432/app next"
    matches = [m for m in scanner.scan(body) if m.type == "db_connection"]
    assert matches
    assert " " not in matches[0].value
    assert matches[0].value.startswith("postgres://")


def test_detect_bearer_token_whitespace():
    scanner = SecretScanner()
    body = "Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123"
    assert any(m.type == "bearer_token" for m in scanner.scan(body))


def test_detect_firebase_and_gcp_oauth_dots():
    scanner = SecretScanner()
    body = "https://demo-app.firebaseio.com token=ya29.a0AfH6SMB_oauth_token_value_xx"
    types = {m.type for m in scanner.scan(body)}
    assert "firebase_url" in types
    assert "gcp_oauth" in types


def test_detect_sendgrid_key_dots():
    scanner = SecretScanner()
    # 22 + 43 char segments required by pattern
    body = "SG." + ("a" * 22) + "." + ("b" * 43)
    assert any(m.type == "sendgrid_key" for m in scanner.scan(body))
