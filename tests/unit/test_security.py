from app.security import CSRFTokenManager, RateLimiter


def test_rate_limiter_allows_within_limit():
    rl = RateLimiter(max_requests=3, window_seconds=60)
    assert all(rl.is_allowed("k") for _ in range(3))
    assert not rl.is_allowed("k")


def test_rate_limiter_isolates_keys():
    rl = RateLimiter(max_requests=1, window_seconds=60)
    assert rl.is_allowed("a")
    assert rl.is_allowed("b")
    assert not rl.is_allowed("a")


def test_rate_limiter_window_expiry():
    rl = RateLimiter(max_requests=1, window_seconds=0)
    assert rl.is_allowed("k")
    assert rl.is_allowed("k")  # zero-length window: previous request already expired


def test_csrf_token_single_use():
    mgr = CSRFTokenManager()
    token = mgr.generate_token()
    assert mgr.validate_token(token)
    assert not mgr.validate_token(token)  # consumed
    assert not mgr.validate_token("forged")
