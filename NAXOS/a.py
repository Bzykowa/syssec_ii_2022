from common_protocol import Initiator
from klib import jstore, jload
from mcl import G1
from party import Party, LAM, GROUP_INIT
import sys

sys.path.insert(1, "/home/karolina/mcl-python")
HOSTNAME = "localhost"
PORT = 15000


class A(Initiator, Party):
    def __init__(self, GROUP_INIT, address: str, port: int, LAM: int) -> None:
        Initiator.__init__(self, address, port)
        Party.__init__(self, GROUP_INIT, LAM)

    def create_session_key(self):
        """Create K = H(Y ^ sk, pk_b ^ x, Y ^ x, A, B)"""
        p1 = self.Y * self.sk
        p2 = self.pk_Y * self.x
        p3 = self.Y * self.x

        self.hash.update((str(p1) + str(p2) + str(p3) + "A" + "B").encode())
        self.K = self.hash.digest()


if __name__ == "__main__":
    a = A(GROUP_INIT, HOSTNAME, PORT, LAM)

    a.send_message(message=jstore({"pk_A": a.pk}))

    m1 = a.receive_message()
    pk_b = jload({"pk_B": G1}, m1, True)["pk_B"]
    a.receive_pk(pk_b)

    X = a.create_X()
    a.send_message(message=jstore({"X": X}))

    m2 = a.receive_message()
    Y = jload({"Y": G1}, m2, True)["Y"]
    a.receive_Y(Y)

    a.create_session_key()
    a.print_session_key()
