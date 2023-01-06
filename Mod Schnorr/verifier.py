from mcl import G1, G2, Fr, GT
import sys
from common_protocol import Responder
from jlib import jload, jstore

sys.path.insert(1, "/home/karolina/mcl-python")
group_init = b"modified_schnorr_is"
HOSTNAME = "localhost"
PORT = 15000


class Verifier(Responder):

    def __init__(self, group_init, address: str, port: int) -> None:
        super().__init__(address, port)
        self.g = G2.hashAndMapTo(group_init)
        self.c = Fr()

    def receive_public_key(self, A):
        """Get A = g^a from Prover"""
        self.A = A

    def receive_X(self, X):
        """Get X = g^x from Prover"""
        self.X = X

    def create_c(self):
        """Generate random challenge value"""
        self.c.setByCSPRNG()
        return self.c

    def create_g_hat(self):
        """Create g_hat = H(X|c)"""
        self.g_hat = G1.hashAndMapTo((str(self.X)+str(self.c)).encode())

    def receive_S(self, S):
        """Get S = g_hat ^ (x + a*c) from Prover"""
        self.S = S

    def check_prover(self) -> bool:
        """Check if Prover submitted correct values"""
        left = GT.pairing(self.S, self.g)
        right = GT.pairing(self.g_hat, self.X + self.A * self.c)
        return left == right


if __name__ == "__main__":
    verifier = Verifier(group_init, HOSTNAME, PORT)

    m1 = verifier.receive_message()
    A, X = jload({"A": G2, "X": G2}, m1)
    verifier.receive_public_key(A)
    verifier.receive_X(X)

    # Get c from Verifier
    c = verifier.create_c()
    verifier.send_message(jstore({"c": c}))

    verifier.create_g_hat()
    m3 = verifier.receive_message()
    S = jload({"S": G1}, m3)[0]
    verifier.receive_S(S)

    result = "Accepted" if verifier.check_prover() else "Rejected"
    verifier.send_message(result)
    print(result)
