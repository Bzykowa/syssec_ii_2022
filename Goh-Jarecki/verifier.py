import argparse
import sys
from common_protocol import Responder
from klib import jload
from mcl import Fr, G2

sys.path.insert(1, "/home/karolina/mcl-python")
GROUP_INIT = b"goh_jarecki"
GROUP_TYPE = G2


class Verifier(Responder):
    def __init__(self, ip: str, port: int, g: GROUP_TYPE) -> None:
        super().__init__(ip, port)
        self.g = g

    def verify(self, m: str, sigma: tuple, A: GROUP_TYPE) -> bool:
        rn, A_hat, s, h = sigma
        g_hat = GROUP_TYPE.hashAndMapTo((m + str(rn)).encode())

        u = (self.g * s) - (A * h)
        v = (g_hat * s) - (A_hat * h)

        h_verification = Fr.setHashOf(
            (str(self.g) + str(g_hat) +
             str(A) + str(A_hat) + str(u) + str(v)).encode()
        )

        return h == h_verification


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Goh Jarecki Signature Scheme - Verifier")

    parser.add_argument("--ip", default="localhost",
                        help="IP address to bind to. Default: localhost")

    parser.add_argument("--port", default=15000, type=int,
                        help="Port to bind to. Default: 15000")
    args = parser.parse_args()

    group = GROUP_TYPE.hashAndMapTo(GROUP_INIT)
    verifier = Verifier(args.ip, args.port, group)

    message = verifier.receive_message()
    data = jload({"m": str, "sigma": (
        Fr, GROUP_TYPE, Fr, Fr), "A": GROUP_TYPE}, message, True)

    if verifier.verify(data["m"], data["sigma"], data["A"]):
        print("Accepted")
    else:
        print("Rejected")
