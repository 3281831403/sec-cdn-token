"""sec-cdn-token 的 15 个行为测试。

全部使用固定输入：不联网、不使用随机数、不读取系统时间。
前 10 个测试分别对应题面中的 10 个缺陷，后 5 个覆盖正确路径。
"""

from cdn.token import (
    cdn_batch,
    expiry_ok,
    normalize_path,
    referer_ok,
    sign_token,
    token_scope,
    validate_policy,
    verify_token,
)

SECRET = "gsb-2026-cdn-secret"
NOW = 1_800_000_000
EXPIRES = NOW + 300
ALLOW = ["example.com", "*.video.example.com"]
POLICY = {
    "secret": SECRET,
    "allow": ALLOW,
    "max_ttl": 600,
    "scope": "/video/2024",
}


def test_defect_01_query_string_is_removed():
    assert normalize_path("/video/2024/a.mp4?token=abc") == "/video/2024/a.mp4"
    assert normalize_path("/video/2024/a.mp4?token=abc&quality=hd") == "/video/2024/a.mp4"


def test_defect_02_duplicate_slashes_are_collapsed():
    assert normalize_path("//video///2024//a.mp4") == "/video/2024/a.mp4"
    assert normalize_path("/video/2024//a.mp4") == "/video/2024/a.mp4"


def test_defect_03_scope_is_not_the_site_root():
    scope = token_scope("/video/2024/a.mp4")
    assert scope == "/video/2024/a.mp4"
    token = sign_token(SECRET, scope, EXPIRES)
    assert verify_token(SECRET, token, token_scope("/music/2024/b.mp3"), NOW) is False


def test_defect_04_scope_prefix_respects_path_boundary():
    token = sign_token(SECRET, "/video", EXPIRES)
    assert verify_token(SECRET, token, "/video/2024/a.mp4", NOW) is True
    assert verify_token(SECRET, token, "/video", NOW) is True
    assert verify_token(SECRET, token, "/video2/2024/a.mp4", NOW) is False


def test_defect_05_token_carries_expiry():
    token = sign_token(SECRET, "/video/2024/a.mp4", EXPIRES)
    parts = token.split(":")
    assert len(parts) == 3
    assert parts[0] == "/video/2024/a.mp4"
    assert parts[1] == str(EXPIRES)
    assert len(parts[2]) == 64
    assert verify_token(SECRET, token, "/video/2024/a.mp4", EXPIRES + 1) is False


def test_defect_06_expiry_boundary_is_rejected():
    token = sign_token(SECRET, "/video/2024/a.mp4", EXPIRES)
    assert verify_token(SECRET, token, "/video/2024/a.mp4", EXPIRES - 1) is True
    assert verify_token(SECRET, token, "/video/2024/a.mp4", EXPIRES) is False
    assert expiry_ok(EXPIRES, EXPIRES, 600) is False


def test_defect_07_ttl_upper_bound_is_enforced():
    assert expiry_ok(NOW + 600, NOW, 600) is True
    assert expiry_ok(NOW + 601, NOW, 600) is False
    assert expiry_ok(NOW + 300, NOW, 600) is True


def test_defect_08_referer_suffix_spoofing_is_rejected():
    assert referer_ok("https://example.com/watch/1", ["example.com"]) is True
    assert referer_ok("https://evil-example.com/watch/1", ["example.com"]) is False
    assert referer_ok("https://example.com.evil.test/watch/1", ["example.com"]) is False
    assert referer_ok("https://a.video.example.com/play", ["*.video.example.com"]) is True
    assert referer_ok("https://video.example.com/play", ["*.video.example.com"]) is False
    assert referer_ok("https://a.video.example.com.evil.test/play", ["*.video.example.com"]) is False


def test_defect_09_policy_scope_too_wide_is_reported():
    wide_root = {"secret": SECRET, "allow": ALLOW, "max_ttl": 600, "scope": "/"}
    wide_top = {"secret": SECRET, "allow": ALLOW, "max_ttl": 600, "scope": "/video"}
    good = {"secret": SECRET, "allow": ALLOW, "max_ttl": 600, "scope": "/video/2024"}
    assert "scope_too_wide" in validate_policy(wide_root)
    assert "scope_too_wide" in validate_policy(wide_top)
    assert validate_policy(good) == []


def test_defect_10_batch_does_not_reuse_previous_scope():
    requests = [
        {
            "path": "/video/2024/a.mp4",
            "referer": "https://example.com/watch/1",
            "token": sign_token(SECRET, "/video/2024/a.mp4", EXPIRES),
        },
        {
            "path": "/video/2024/b.mp4",
            "referer": "https://example.com/watch/2",
            "token": sign_token(SECRET, "/video/2024/b.mp4", EXPIRES),
        },
    ]
    assert cdn_batch(requests, POLICY, NOW) == {0: True, 1: True}


def test_valid_token_passes():
    scope = token_scope("/video/2024/a.mp4")
    token = sign_token(SECRET, scope, EXPIRES)
    assert verify_token(SECRET, token, scope, NOW) is True


def test_cross_directory_token_is_rejected():
    token = sign_token(SECRET, "/video/2024", EXPIRES)
    assert verify_token(SECRET, token, "/video/2024/a.mp4", NOW) is True
    assert verify_token(SECRET, token, "/video/2025/a.mp4", NOW) is False


def test_expired_token_is_rejected():
    token = sign_token(SECRET, "/video/2024/a.mp4", EXPIRES)
    assert verify_token(SECRET, token, "/video/2024/a.mp4", EXPIRES + 1) is False
    assert verify_token(SECRET, token, "/video/2024/a.mp4", NOW) is True


def test_spoofed_referer_is_rejected():
    assert referer_ok("https://www.example.com/watch", ["www.example.com"]) is True
    assert referer_ok("https://www.example.com.attacker.test/watch", ["www.example.com"]) is False
    assert referer_ok("https://notwww.example.com/watch", ["www.example.com"]) is False


def test_batches_independent_match_individual():
    first = {
        "path": "/video/2024/a.mp4",
        "referer": "https://example.com/watch/1",
        "token": sign_token(SECRET, "/video/2024/a.mp4", EXPIRES),
    }
    second = {
        "path": "/video/2024/b.mp4",
        "referer": "https://a.video.example.com/watch/2",
        "token": sign_token(SECRET, "/video/2024/b.mp4", EXPIRES),
    }
    outside = {
        "path": "/music/2024/c.mp3",
        "referer": "https://example.com/watch/3",
        "token": sign_token(SECRET, "/music/2024/c.mp3", EXPIRES),
    }

    assert cdn_batch([first, second], POLICY, NOW) == {0: True, 1: True}
    assert cdn_batch([first], POLICY, NOW) == {0: True}
    assert cdn_batch([second], POLICY, NOW) == {0: True}
    assert cdn_batch([outside], POLICY, NOW) == {0: False}