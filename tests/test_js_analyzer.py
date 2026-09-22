"""Regression tests for js_analyzer raw-string regex fixes (P1)."""
import re
from gungnir.native.js_analyzer import (
    API_ROUTE_PATTERNS,
    PARAM_PATTERNS,
    SECRET_PATTERNS,
    _extract_js_urls,
    _extract_patterns,
)


def test_api_route_literal_path():
    routes = _extract_patterns('const u = "/api/users/{id}";', API_ROUTE_PATTERNS)
    assert "/api/users/{id}" in routes


def test_fetch_and_axios_call_patterns():
    js = 'fetch("/api/items"); axios.get(`/v1/orders`);'
    routes = _extract_patterns(js, API_ROUTE_PATTERNS)
    assert "/api/items" in routes
    assert "/v1/orders" in routes


def test_jquery_ajax_url_pattern():
    js = '$.ajax({url: "/api/search", method: "GET"});'
    routes = _extract_patterns(js, API_ROUTE_PATTERNS)
    assert "/api/search" in routes


def test_param_word_pattern():
    params = _extract_patterns('"user=" + id', PARAM_PATTERNS)
    assert "user" in params


def test_jwt_secret_in_js():
    token = (
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    jwt_pat = [p for p, t in SECRET_PATTERNS if t == "jwt"][0]
    assert re.search(jwt_pat, token)


def test_extract_js_urls_from_script_src():
    html = (
        '<script src="/static/main.js"></script>'
        "<script src='https://cdn.example/app.js'></script>"
    )
    urls = _extract_js_urls(html, "https://target.example")
    assert "https://target.example/static/main.js" in urls
    assert "https://cdn.example/app.js" in urls
