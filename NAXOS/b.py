from common_protocol import Responder
from klib import jstore, jload
from mcl import G1
from party import Party, LAM, GROUP_INIT
import sys

sys.path.insert(1, "/home/karolina/mcl-python")
HOSTNAME = "localhost"
PORT = 15000


class B(Responder, Party):
    def __init__(self, GROUP_INIT, address: str, port: int, LAM: int) -> None:
        Responder.__init__(self, address, port)
        Party.__init__(self, GROUP_INIT, LAM)

    def create_session_key(self):
        """Create K = H(pk_a ^ x, Y ^ sk, Y ^ x, A, B)"""
        p1 = self.pk_Y * self.x
        p2 = self.Y * self.sk
        p3 = self.Y * self.x

        self.hash.update((str(p1) + str(p2) + str(p3) + "A" + "B").encode())
        self.K = self.hash.digest()


if __name__ == "__main__":
    b = B(GROUP_INIT, HOSTNAME, PORT, LAM)

    m1 = b.receive_message()
    pk_a = jload({"pk_A": G1}, m1, True)["pk_A"]
    b.receive_pk(pk_a)

    b.send_message(message=jstore({"pk_B": b.pk}))

    m2 = b.receive_message()
    X = jload({"X": G1}, m2, True)["X"]
    b.receive_Y(X)

    Y = b.create_X()
    b.send_message(message=jstore({"Y": Y}))

    b.create_session_key()
    b.print_session_key()
