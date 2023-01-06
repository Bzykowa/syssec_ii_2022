from mcl import G1, Fr
import sys
from common_protocol import Responder
from jlib import jload, jstore

sys.path.insert(1, "/home/karolina/mcl/mcl-python")
group_init = b"okamoto_is"
HOSTNAME = "localhost"
PORT = 15000


class Verifier(Responder):

    def __init__(self, group_init, address, port):
        super().__init__(address, port)
        self.g1 = G1.hashAndMapTo(group_init)
        self.g2 = G1.hashAndMapTo(group_init+group_init)
        self.c = Fr()
        self.s1 = Fr()
        self.s2 = Fr()

    def receive_public_key(self, A):
        """Get A = g1^a1 * g2^a2 from Prover"""
        self.A = A

    def receive_X(self, X):
        """Get X = g1^x1 * g2^x2 from Prover"""
        self.X = X

    def create_c(self):
        """Generate random challenge value"""
        self.c.setByCSPRNG()
        return self.c

    def receive_s1_s2(self, s1, s2):
        """Get s1 = x1 + a1*c; s2 = x2 + a2*c from Prover"""
        self.s1 = s1
        self.s2 = s2

    def check_prover(self) -> bool:
        """Check if Prover submitted correct values"""
        return (
            self.g1 * self.s1 + self.g2 * self.s2 == self.X + (self.A * self.c)
        )


if __name__ == "__main__":
    verifier = Verifier(group_init, HOSTNAME, PORT)

    m1 = verifier.receive_message()
    A = jload({"A": G1}, m1)[0]
    verifier.receive_public_key(A)

    m2 = verifier.receive_message()
    X = jload({"X": G1}, m2)[0]
    verifier.receive_X(X)

    # Get c from Verifier
    c = verifier.create_c()
    verifier.send_message(jstore({"c": c}))

    m3 = verifier.receive_message()
    s = jload({"s1": Fr, "s2": Fr}, m3)
    verifier.receive_s1_s2(s[0], s[1])

    result = "Accepted" if verifier.check_prover() else "Rejected"
    verifier.send_message(result)
    print(result)
