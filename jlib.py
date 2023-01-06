import json


def jstore(d):
    return json.dumps(
        {k: v.getStr().decode() if type(v) != bytes else v.hex()
         for k, v in d.items()}
    )


def jload(d, j):
    j = json.loads(j)
    r = []
    for k, t in d.items():
        if t != bytes:
            v = t()
            v.setStr(j[k].encode())
        else:
            v = t.fromhex(j[k])
        r.append(v)
    return r
