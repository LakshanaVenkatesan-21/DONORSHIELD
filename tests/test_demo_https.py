"""Focused checks for the opt-in localhost HTTPS demo mode."""
from __future__ import annotations

from cryptography import x509


def _capture_session_cookie(app):
    with app.test_request_context("/"):
        from flask import session

        session["demo_probe"] = True
        response = app.make_response("")
        app.session_interface.save_session(app, session, response)
        return response.headers["Set-Cookie"]


def test_demo_http_remains_default_and_cookie_is_not_secure(monkeypatch):
    import app as app_module
    import demo_setup

    monkeypatch.setattr(demo_setup, "prepare_demo", lambda: None)
    run_args = {}
    monkeypatch.setattr(app_module.app, "run", lambda **kwargs: run_args.update(kwargs))
    monkeypatch.setitem(app_module.app.config, "SESSION_COOKIE_SECURE", True)

    demo_setup.run_demo()

    assert app_module.app.config["SESSION_COOKIE_SECURE"] is False
    assert app_module.app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert app_module.app.config["SESSION_COOKIE_SAMESITE"] == "Lax"
    assert "Secure" not in _capture_session_cookie(app_module.app)
    assert run_args["ssl_context"] is None
    assert run_args["host"] == "127.0.0.1"


def test_demo_https_uses_local_certificate_and_secure_cookie(monkeypatch, tmp_path):
    import app as app_module
    import demo_setup

    monkeypatch.setattr(demo_setup, "prepare_demo", lambda: None)
    monkeypatch.setattr(demo_setup, "DEMO_TLS_CERT", tmp_path / "localhost.crt")
    monkeypatch.setattr(demo_setup, "DEMO_TLS_KEY", tmp_path / "localhost.key")
    run_args = {}
    monkeypatch.setattr(app_module.app, "run", lambda **kwargs: run_args.update(kwargs))

    demo_setup.run_demo(https=True)

    assert app_module.app.config["SESSION_COOKIE_SECURE"] is True
    assert app_module.app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert app_module.app.config["SESSION_COOKIE_SAMESITE"] == "Lax"
    cookie = _capture_session_cookie(app_module.app)
    assert "Secure" in cookie
    assert "HttpOnly" in cookie
    assert "SameSite=Lax" in cookie
    assert run_args["ssl_context"] == (
        str(tmp_path / "localhost.crt"), str(tmp_path / "localhost.key")
    )
    assert run_args["host"] == "127.0.0.1"

    cert_bytes = (tmp_path / "localhost.crt").read_bytes()
    key_bytes = (tmp_path / "localhost.key").read_bytes()
    cert = x509.load_pem_x509_certificate(cert_bytes)
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert "localhost" in san.get_values_for_type(x509.DNSName)
    assert demo_setup.ensure_demo_tls_certificate() == (
        tmp_path / "localhost.crt", tmp_path / "localhost.key"
    )
    assert (tmp_path / "localhost.crt").read_bytes() == cert_bytes
    assert (tmp_path / "localhost.key").read_bytes() == key_bytes


def test_incomplete_demo_certificate_pair_is_not_overwritten(monkeypatch, tmp_path):
    import demo_setup

    cert_path = tmp_path / "localhost.crt"
    key_path = tmp_path / "localhost.key"
    cert_path.write_text("existing certificate placeholder", encoding="ascii")
    monkeypatch.setattr(demo_setup, "DEMO_TLS_CERT", cert_path)
    monkeypatch.setattr(demo_setup, "DEMO_TLS_KEY", key_path)

    import pytest
    with pytest.raises(RuntimeError, match="refusing to replace"):
        demo_setup.ensure_demo_tls_certificate()
    assert cert_path.read_text(encoding="ascii") == "existing certificate placeholder"
    assert not key_path.exists()
