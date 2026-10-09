"""Full Telegram native-handler regression shared with Android instrumentation."""
import datetime
import importlib.util
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


@pytest.mark.asyncio
async def test_concurrent_native_media_real_tls_websockets_and_crypto(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(hours=1))
            .add_extension(x509.SubjectAlternativeName([
                x509.DNSName(host) for host in ['localhost'] + [
                    f'kws{dc}{suffix}.web.telegram.org'
                    for dc in range(1, 6) for suffix in ('', '-1')]
            ]), critical=False)
            .sign(key, hashes.SHA256()))
    cert_path, key_path = tmp_path / 'cert.pem', tmp_path / 'key.pem'
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                         serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()))
    source = Path(__file__).parents[1] / 'app/src/androidTest/assets/telegram_wire_check.py'
    spec = importlib.util.spec_from_file_location('telegram_wire_check', source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    result = await module.run(str(cert_path), str(key_path))
    assert result['clients'] == 12
    assert result['media_clients'] == 8
    assert result['received_bytes'] > 16 * 1024 * 1024
    assert result['transport_error_forwarded'] == -404
    assert result['third_party_routes'] == 0
    assert result['cdn_203'] == 'native_tcp'
