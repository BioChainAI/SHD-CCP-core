"""Independent Python reference for the fixed Einstein Tile field positions only.
Not an authentication system and not full Form-specific validation.
"""
FIELDS = (("core", 0, 32), ("scale", 32, 4), ("stream_slot", 36, 4),
          ("form_id", 40, 4), ("step_index", 44, 4), ("gate", 48, 8),
          ("structure", 56, 2), ("wheel_unit", 58, 3), ("cycle_step", 61, 3))

def pack(**kwargs):
    out = 0
    for name, lsb, width in FIELDS:
        value = kwargs.get(name, 0)
        if not isinstance(value, int) or value < 0 or value >= (1 << width):
            raise ValueError(f"field out of range: {name}")
        out |= value << lsb
    return out.to_bytes(8, "big")

def unpack(raw):
    if len(raw) != 8:
        raise ValueError("required exactly 8 bytes")
    word = int.from_bytes(raw, "big")
    return {name: (word >> pos) & ((1 << width) - 1)
            for name, pos, width in FIELDS}

def parity_3x1(a, b, c):
    return a ^ b ^ c
