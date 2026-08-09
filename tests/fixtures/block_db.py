import sqlite3


async def get_user(user_id: int):
    conn = sqlite3.connect(":memory:")
    conn.close()
