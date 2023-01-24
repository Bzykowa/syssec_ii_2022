import argparse
import sys

from mcl import Fr, G1
from party import GROUP_INIT, GROUP_TYPE, Party

from common_protocol import Initiator
from klib import jload, jstore

sys.path.insert(1, "/home/karolina/mcl-python")


class A(Initiator, Party):
    def __init__(self, ip: str, port: int, g: GROUP_TYPE) -> None:
        Initiator.__init__(self, ip, port)
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
    a = A(args.ip, args.port, group)
    X = a.create_ephemerals(True)
    a.send_message(jstore({"s": a.s, "X": X, "A": a.pk}))

    m1 = a.receive_message()
    data = jload(
        {"Y": GROUP_TYPE, "sigma_b": (GROUP_TYPE, Fr),
         "MAC_b": GROUP_TYPE, "cert_b": GROUP_TYPE, "B": GROUP_TYPE},
        m1,
        True
    )

    a.receive_other_pk(data["B"])
    a.receive_other_eph_pk(data["Y"])
    a.calculate_intermediate_keys()

    sign_X, sign_s = data["sigma_b"]
    sign_m = str(a.s) + "1" + str(X) + str(data["Y"])

    if a.check_MAC(data["MAC_b"], data["cert_b"]):
        print("MAC correct")
    else:
        raise ValueError("Incorrect MAC")
    if a.verify_signature(sign_X, sign_m, sign_s):
        print("Signature correct")
    else:
        raise ValueError("Incorrect signature")

    cert_a = G1.hashAndMapTo(b"certificate_a")
    sign_m = str(a.s) + "0" + str(X) + str(data["Y"])
    sigma_a = a.sign(sign_m)
    mac_a = a.calculate_MAC(cert_a)

    a.send_message(
        jstore({"sigma_a": sigma_a, "MAC_a": mac_a, "cert_a": cert_a})
    )
    a.print_session_key()
