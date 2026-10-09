"""Local HTTPS for a separate Android UID. Test key/CA never enters the app APK."""
import asyncio
import datetime
import base64
import hashlib
import ssl
import sys
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

BODY=bytes(i%251 for i in range(1024*1024))

async def main(directory):
    root=Path(directory); root.mkdir(parents=True,exist_ok=True)
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'GrayBridge local test')])
    now=datetime.datetime.now(datetime.timezone.utc)
    cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=1))
          .not_valid_after(now+datetime.timedelta(days=1)).add_extension(x509.SubjectAlternativeName(
              [x509.DNSName(h) for h in ('normal.example.test','www.youtube.com','discord.com','gateway.discord.gg',
                                       'chatgpt.com','claude.ai','gemini.google.com','instagram.com','scontent.cdninstagram.com')]),False).sign(key,hashes.SHA256()))
    (root/'cert.der').write_bytes(cert.public_bytes(serialization.Encoding.DER))
    (root/'cert.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (root/'key.pem').write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(root/'cert.pem',root/'key.pem')
    ctx.set_servername_callback(lambda sock,host,context:print('TLS SNI',host,flush=True))
    async def serve(reader,writer):
        try:
            request=await reader.readuntil(b'\r\n\r\n')
            if b'upgrade: websocket' in request.lower():
                headers=dict(line.split(':',1) for line in request.decode('ascii').split('\r\n')[1:] if ':' in line)
                key=headers['Sec-WebSocket-Key'].strip()
                accept=base64.b64encode(hashlib.sha1((key+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest())
                writer.write(b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: '+accept+b'\r\n\r\n')
                body=b'{"op":10,"d":{"heartbeat_interval":45000}}'
                writer.write(bytes([0x81,len(body)])+body);await writer.drain()
                await asyncio.wait_for(reader.read(512),5)
                print('WSS delivered Discord Hello',flush=True)
                return
            writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: 1048576\r\nConnection: close\r\n\r\n')
            for offset in range(0,len(BODY),4096):
                writer.write(BODY[offset:offset+4096]); await writer.drain()
            print('HTTPS delivered',len(BODY),flush=True)
        finally:
            writer.close()
            try: await writer.wait_closed()
            except OSError: pass
    server=await asyncio.start_server(serve,'0.0.0.0',18890,ssl=ctx)
    async with server: await server.serve_forever()

if __name__=='__main__':asyncio.run(main(sys.argv[1]))
