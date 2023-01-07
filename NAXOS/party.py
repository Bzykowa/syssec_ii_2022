from hashlib import sha256
import sys
from mcl import G1, Fr
from random import getrandbits

sys.path.insert(1, "/home/karolina/mcl-python")
GROUP_INIT = b"naxos_ake"
LAM = 256


class Party:
    def __init__(self, GROUP_INIT, LAM) -> None:
        self.g = G1.hashAndMapTo(GROUP_INIT)
        self.lam = LAM
        self.sk = Fr()
        self.esk = getrandbits(self.lam)
        self.hash = sha256()
        self.x = Fr()
        self.X = None
        self.pk_Y = None
        self.Y = None
        self.K = None

        # Generate public key
        self.sk.setByCSPRNG()
        self.pk = self.g * self.sk

    def receive_pk(self, pk_Y):
        """Receive the public key of the other party"""
        self.pk_Y = pk_Y

    def create_X(self):
        """Create X = g ^ H(esk,sk)."""
        self.x = Fr.setHashOf((str(self.esk) + str(self.sk)).encode())
        self.X = self.g * self.x
        return self.X

    def receive_Y(self, Y):
        """Receive Y from the other party."""
        self.Y = Y

    def print_session_key(self):
        print("K: " + self.K.hex())
