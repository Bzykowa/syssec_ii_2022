import json
from typing import Union


class MCLJsonEncoder(json.JSONEncoder):
    """JSON encoder capable of properly encoding mcl structures."""

    def default(self, o):
        if hasattr(o, "getStr"):
            return o.getStr().decode() if type(o) != bytes else o.hex()
        else:
            return json.JSONEncoder.default(self, o)


def jload(expected_values: dict, json_str: str, return_dict: bool = False) -> Union[dict, list]:
    """
    Decode JSON string.

    By default it returns a list for backwards compatibility. 
    return_dict=True is suggested for convenience.
    """
    preprocessed_dict = json.loads(json_str)
    result = {} if return_dict else []

    for key, val in expected_values.items():
        type = val
        decoded = __parse_single(type, preprocessed_dict[key])

        if return_dict:
            result[key] = decoded
        else:
            result.append(decoded)

    return result


def __parse_single(cls, str_or_list):
    try:
        iter(cls)
        iterable = True
    except TypeError as te:
        iterable = False

    if iterable:
        decoded = []
        # assume homogenous
        if len(cls) == 1:
            list = [cls[0] for i in range(len(str_or_list))]
        elif len(cls) == len(str_or_list):
            list = cls
        else:
            raise Exception(
                "Expected list has different length than list in JSON.")
        for i, single in enumerate(str_or_list):
            # yes its recurrent, sue me
            decoded.append(__parse_single(list[i], single))
        decoded = type(cls)(decoded)
    else:
        object = str_or_list
        if not isinstance(object, cls) if cls != None else cls != None:
            if cls != bytes:
                decoded = cls()
                decoded.setStr(object.encode())
            else:
                decoded = cls.fromhex(object)
        else:
            decoded = object
    return decoded


def jstore(dictionary: dict) -> str:
    """Encode dictionary as a JSON string."""
    return json.dumps(dictionary, cls=MCLJsonEncoder)


def __jstore(d: dict) -> str:
    return json.dumps({k: v.getStr().decode() if type(v) != bytes else v.hex() for k, v in d.items()})


def __jload_single(d: dict, j: str) -> dict:
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
