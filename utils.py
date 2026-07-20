def normalize_name(name):
    if name == ".":
        return name
    return name.rstrip(".").lower() + "."
