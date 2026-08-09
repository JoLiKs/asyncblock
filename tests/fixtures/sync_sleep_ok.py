import asyncio
import time


def sync_worker():
    time.sleep(1)


async def async_worker():
    await asyncio.sleep(1)
