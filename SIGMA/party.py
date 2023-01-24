import sys
from mcl import G1, Fr

sys.path.insert(1, "/home/karolina/mcl-python")
GROUP_TYPE = G1
GROUP_INIT = b"sigma_ake"


class Party:
    def __init__(self, g: GROUP_TYPE) -> None:
        self.g = g
        self.sk = Fr()
        self.pk = None
        self.other_pk = None

        self.s = None
        self.eph_sk = Fr()
        self.eph_pk = None
        self.other_eph_pk = None
        self.K = None
        self.K0 = None
        self.K1 = None

        # Generate public key
        self.sk.setByCSPRNG()
        self.pk = self.g * self.sk

    def create_ephemerals(self, is_initiator: bool):
        """Create ephemeral keys."""
        self.eph_sk.setByCSPRNG()
        self.eph_pk = self.g * self.eph_sk
        if is_initiator:
            self.s = Fr()
            self.s.setByCSPRNG()
        return self.eph_pk

    def receive_other_pk(self, pk: GROUP_TYPE) -> None:
        self.other_pk = pk

    def receive_other_eph_pk(self, pk: GROUP_TYPE) -> None:
        self.other_eph_pk = pk

    def receive_s(self, s: Fr) -> None:
        self.s = s

    def calculate_intermediate_keys(self) -> None:
        """Create keys that will be used to perform authentication
         and to establish the session key."""
        self.K = self.other_pk * self.sk
        self.K0 = GROUP_TYPE.hashAndMapTo((str(self.K) + "0").encode())
        self.K1 = GROUP_TYPE.hashAndMapTo((str(self.K) + "1").encode())

    def sign(self, m: str):
        "Create signed message s = x + a*h"
        x = Fr()
        x.setByCSPRNG()
        X = self.g * x
        h = Fr.setHashOf((str(X) + m).encode())
        s = x + self.sk * h
        return X, s

    def verify_signature(self, X, m: str, s: Fr) -> bool:
        """Verify the signature."""
        h = Fr.setHashOf((str(X) + m).encode())
        return self.g * s == X + (self.other_pk*h)

    def calculate_MAC(self, cert: GROUP_TYPE) -> GROUP_TYPE:
        return GROUP_TYPE.hashAndMapTo(
            (str(self.K0) + str(self.s) + str(cert)).encode()
        )

    def check_MAC(self, mac: GROUP_TYPE, cert: GROUP_TYPE) -> bool:
        return mac == self.calculate_MAC(cert)

    def print_session_key(self) -> None:
        print(self.K1)
