def ready(world):
    policy = (world or {}).get("policy") or {}
    vendors = [str(name).lower() for name in policy.get("approved_vendors") or []]
    return policy.get("max_amount") == 1000 and "northwind" in vendors and "acme" in vendors
