import argparse
import sys

from mcl import Fr, G1
from party import GROUP_INIT, GROUP_TYPE, Party

from common_protocol import Responder
from klib import jload, jstore

sys.path.insert(1, "/home/karolina/mcl-python")


class B(Responder, Party):
    def __init__(self, ip: str, port: int, g: GROUP_TYPE) -> None:
        Responder.__init__(self, ip, port)
        Party.__init__(self, g)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Goh Jarecki Signature Scheme - Verifier")

    parser.add_argument("--ip", default="localhost",
                        help="IP address to bind to. Default: localhost")

    parser.add_argument("--port", default=15000, type=int,
                        help="Port to bind to. Default: 15000")
    args = parser.parse_args()

    group = GROUP_TYPE.hashAndMapTo(GROUP_INIT)
    b = B(args.ip, args.port, group)
    Y = b.create_ephemerals(False)

    m1 = b.receive_message()
    data = jload({"s": Fr, "X": GROUP_TYPE, "A": GROUP_TYPE}, m1, True)

    b.receive_other_pk(data["A"])
    b.receive_other_eph_pk(data["X"])
    b.receive_s(data["s"])

    b.calculate_intermediate_keys()
    sign_m = str(data["s"]) + "1" + str(data["X"]) + str(Y)
    cert_b = G1.hashAndMapTo(b"certificate_b")
    sigma_b = b.sign(sign_m)
    mac_b = b.calculate_MAC(cert_b)

    b.send_message(
        jstore(
            {"Y": Y, "sigma_b": sigma_b, "MAC_b": mac_b,
                "cert_b": cert_b, "B": b.pk},
        )
    )

    m2 = b.receive_message()
    data = jload({"sigma_a": (GROUP_TYPE, Fr),
                 "MAC_a": GROUP_TYPE, "cert_a": GROUP_TYPE}, m2, True)

    sign_X, sign_s = data["sigma_a"]
    sign_m = str(b.s) + "0" + str(b.other_eph_pk) + str(Y)

    if b.check_MAC(data["MAC_a"], data["cert_a"]):
        print("MAC correct")
    else:
        raise ValueError("Incorrect MAC")
    if b.verify_signature(sign_X, sign_m, sign_s):
        print("Signature correct")
    else:
        raise ValueError("Incorrect signature")

    b.print_session_key()
