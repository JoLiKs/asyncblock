async def read_config():
    with open("config.json") as f:
        return f.read()
