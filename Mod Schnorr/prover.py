from mcl import G1, G2, Fr
import sys
from common_protocol import Initiator
from jlib import jstore, jload

sys.path.insert(1, "/home/karolina/mcl-python")
group_init = b"modified_schnorr_is"
HOSTNAME = "localhost"
PORT = 15000


class Prover(Initiator):

    def __init__(self, group_init, address: str, port: int) -> None:
        super().__init__(address, port)
        self.g = G2.hashAndMapTo(group_init)
        self.a = Fr()
        self.x = Fr()
        self.c = Fr()

        # Generate public key
        self.a.setByCSPRNG()
        self.A = self.g * self.a

    def send_public_key(self):
        """Return A = g^a which is the public key"""
        return self.A

    def create_X(self):
        """Create X = g^x and return it"""
        self.x.setByCSPRNG()
        self.X = self.g * self.x
        return self.X

    def receive_c(self, c):
        """Get c from Verifier"""
        self.c = c

    def create_g_hat(self):
        """Create g_hat = H(X|c)"""
        self.g_hat = G1.hashAndMapTo((str(self.X)+str(self.c)).encode())

    def create_S(self):
        """Create S = g_hat ^ (x + a*c) and return it"""
        self.S = self.g_hat * (self.x + self.a * self.c)
        return self.S


if __name__ == "__main__":
    prover = Prover(group_init, HOSTNAME, PORT)

    A = prover.send_public_key()
    X = prover.create_X()
    prover.send_message(jstore({"A": A, "X": X}))

    # Get c from Verifier
    m1 = prover.receive_message()
    c = jload({"c": Fr}, m1)[0]
    prover.receive_c(c)

    prover.create_g_hat()
    S = prover.create_S()
    prover.send_message(jstore({"S": S}))

    result = prover.receive_message()
    print(result)
