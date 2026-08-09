import time


async def outer():
    def inner():
        time.sleep(1)

    inner()
