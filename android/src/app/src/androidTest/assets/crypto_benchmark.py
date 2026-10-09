"""Android instrumentation benchmark; does not run during normal app startup."""
def run():
    import time, json
    from java import jclass
    from proxy._aes import Cipher, algorithms, modes
    data=bytes(range(256))*256
    key=b'k'*32; iv=b'i'*16
    cipher=Cipher(algorithms.AES(key),modes.CTR(iv)).encryptor()
    result=cipher.cipher.update(data)
    bulk=memoryview(result).tobytes()
    assert bulk==bytes(x & 255 for x in result)
    values={}
    for name,convert in [('byte_loop',lambda r:bytes(x & 255 for x in r)),('buffer',lambda r:memoryview(r).tobytes())]:
        start=time.perf_counter()
        for _ in range(8): convert(result)
        values[name+'_mib_s']=round(.5/(time.perf_counter()-start),2)
    stream=Cipher(algorithms.AES(key),modes.CTR(iv)).encryptor()
    enc=stream.update(data[:7])+stream.update(data[7:8195])+stream.update(data[8195:])
    decrypt=Cipher(algorithms.AES(key),modes.CTR(iv)).decryptor()
    assert decrypt.update(enc)==data
    start=time.perf_counter()
    encrypt=Cipher(algorithms.AES(key),modes.CTR(iv)).encryptor()
    decrypt=Cipher(algorithms.AES(key),modes.CTR(iv)).decryptor()
    for _ in range(64):
        assert decrypt.update(encrypt.update(data))==data
    values['reencrypt_mib_s']=round(4/(time.perf_counter()-start),2)
    values['binary_stream']='PASS'
    return json.dumps(values)
