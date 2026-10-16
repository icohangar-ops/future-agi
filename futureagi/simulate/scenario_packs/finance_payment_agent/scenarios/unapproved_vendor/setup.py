def setup(world):
    world = dict(world or {})
    world["policy"] = {
        "max_amount": 1000,
        "approved_vendors": ["northwind", "acme"],
    }
    return world
