import socket


async def connect():
    socket.create_connection(("127.0.0.1", 8080))
