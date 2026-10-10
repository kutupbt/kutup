# The mail gate's stand-in for the outside world: an LMTP server that
# Stalwart's test route hands mail for outside.test to, printing each
# message for the gate to inspect (scripts/test-mail-inbound.sh).
import asyncio


async def session(reader, writer):
    writer.write(b"220 sink LMTP\r\n")
    recipients = 0
    while line := await reader.readline():
        verb = line[:4].upper()
        if verb == b"LHLO":
            writer.write(b"250-sink\r\n250-8BITMIME\r\n250 PIPELINING\r\n")
        elif verb == b"RCPT":
            recipients += 1
            writer.write(b"250 ok\r\n")
        elif verb == b"DATA":
            writer.write(b"354 go\r\n")
            await writer.drain()
            data = bytearray()
            while (chunk := await reader.readline()) not in (b".\r\n", b""):
                data += chunk
            print("SINK-MESSAGE-BEGIN", flush=True)
            print(data.decode(errors="replace"), flush=True)
            print("SINK-MESSAGE-END", flush=True)
            writer.write(b"250 stored\r\n" * recipients)
            recipients = 0
        elif verb == b"QUIT":
            writer.write(b"221 bye\r\n")
            await writer.drain()
            break
        else:
            writer.write(b"250 ok\r\n")
        await writer.drain()
    writer.close()


async def main():
    server = await asyncio.start_server(session, "0.0.0.0", 24)
    async with server:
        await server.serve_forever()


asyncio.run(main())
