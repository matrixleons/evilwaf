from unittest.mock import patch

from chemistry.origin_server_ip import OriginVerifier


def test_origin_certificate_uses_verified_tls():
    verifier = OriginVerifier("example.com")

    with patch(
        "chemistry.origin_server_ip.socket.create_connection",
        side_effect=ConnectionRefusedError("offline test"),
    ):
        with patch(
            "chemistry.origin_server_ip.ssl.create_default_context"
        ) as create_context:
            assert verifier.verify_cert("127.0.0.1") is False
            create_context.assert_called_once_with()


def test_origin_certificate_rejects_connection_failure():
    verifier = OriginVerifier("example.com")

    with patch(
        "chemistry.origin_server_ip.socket.create_connection",
        side_effect=OSError("connection failed"),
    ):
        assert verifier.verify_cert("127.0.0.1") is False


def test_connectivity_does_not_confirm_origin():
    from unittest.mock import patch

    verifier = OriginVerifier("example.com")

    with patch.object(verifier, "verify_cert", return_value=True), \
         patch.object(verifier, "verify_http", return_value=True), \
         patch(
             "chemistry.origin_server_ip.StrictIPClassifier.is_definitely_cdn",
             return_value=(False, ""),
         ), \
         patch(
             "chemistry.origin_server_ip._FAST_AVAILABLE",
             False,
         ):
        confirmed, cert_ok, http_ok = verifier.verify("127.0.0.1")

    assert confirmed is False
    assert cert_ok is True
    assert http_ok is True
