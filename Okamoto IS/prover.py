from mcl import G1, Fr
import sys
from common_protocol import Initiator
from jlib import jstore, jload

sys.path.insert(1, "/home/karolina/mcl/mcl-python")
group_init = b"okamoto_is"
HOSTNAME = "localhost"
PORT = 15000


class Prover(Initiator):

    def __init__(self, group_init, address, port):
        super().__init__(address, port)
        self.g1 = G1.hashAndMapTo(group_init)
        self.g2 = G1.hashAndMapTo(group_init+group_init)
        self.a1 = Fr()
        self.a2 = Fr()
        self.x1 = Fr()
        self.x2 = Fr()
        self.c = Fr()
        self.s1 = Fr()
        self.s2 = Fr()

        # Generate public key
        self.a1.setByCSPRNG()
        self.a2.setByCSPRNG()
        self.A = self.g1 * self.a1 + self.g2 * self.a2

    def send_public_key(self):
        """Return A = g1^a1 * g2^a2 which is the public key"""
        return self.A

    def create_X(self):
        """Create X = g1^x1 * g2^x2 and return it"""
        self.x1.setByCSPRNG()
        self.x2.setByCSPRNG()
        self.X = self.g1 * self.x1 + self.g2 * self.x2
        return self.X

    def receive_c(self, c):
        """Get c from Verifier"""
        self.c = c

    def create_s1_s2(self):
        """Create s1 = x1 + a1*c; s2 = x2 + a2*c and return it"""
        self.s1 = self.x1 + self.a1 * self.c
        self.s2 = self.x2 + self.a2 * self.c
        return self.s1, self.s2


if __name__ == "__main__":
    prover = Prover(group_init, HOSTNAME, PORT)

    A = prover.send_public_key()
    prover.send_message(jstore({"A": A}))

    X = prover.create_X()
    prover.send_message(jstore({"X": X}))

    # Get c from Verifier
    m1 = prover.receive_message()
    c = jload({"c": Fr}, m1)[0]
    prover.receive_c(c)

    s1, s2 = prover.create_s1_s2()
    prover.send_message(jstore({"s1": s1, "s2": s2}))

    result = prover.receive_message()
    print(result)
