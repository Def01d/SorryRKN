"""Local test server for the separate Android network probe; no Internet needed."""
import asyncio

class UDP(asyncio.DatagramProtocol):
    def connection_made(self,transport): self.transport=transport
    def datagram_received(self,data,addr): self.transport.sendto(data,addr)

async def echo(reader,writer):
    print('Accepted TCP', writer.get_extra_info('peername'), flush=True)
    try:
        data=await reader.readexactly(128*1024)
        print('Received TCP bytes', len(data), flush=True)
        writer.write(data[::-1]); await writer.drain()
    finally:
        writer.close(); await writer.wait_closed()

async def main():
    server=await asyncio.start_server(echo,'0.0.0.0',18888)
    transport,_=await asyncio.get_running_loop().create_datagram_endpoint(UDP,local_addr=('0.0.0.0',18889))
    try:
        async with server: await server.serve_forever()
    finally: transport.close()

if __name__=='__main__': asyncio.run(main())
