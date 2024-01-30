import secrets
import warnings
import hashlib

from typing import Self, Tuple
from sage.all import Zmod, Integer, inverse_mod

# Used for typing purposes
from sage.rings.finite_rings.integer_mod import IntegerMod_int

"""ECDSA^2 Implementation

This module implements a skeleton ECDSA^2 KeyGen, Verification and Signing.

Authors:
    Jan Gilcher, Kien Tuong Truong
"""


def hash_message_to_bits(msg: str):
    """Hash a string to a string of bits

    Args:
        msg (str): The message to be hashed

    Returns:
        str: a binary string in big-endian format that represents the hash of msg
    """

    h = hashlib.sha256()
    h.update(msg.encode())
    h_as_bits = ''.join(format(byte, '08b') for byte in h.digest())
    return h_as_bits

def bits_to_int(h_as_bits: str, q: int) -> IntegerMod_int:
    """Convert a truncated binary string in big-endian format to an integer modulo q

    Args:
        h_as_bits: a binary string in big-endian format
        q: the modulus of the result

    Returns:
        IntegerMod_int: the integer representation of h_as_bits in the ring of integers mod q
    """

    return Zmod(q)(Integer(h_as_bits, base=2))

class Curve:
    """An elliptic curve over the integers modulo p

    Technically speaking, curves are defined over a field, but all the operations
    we need are supported in the ring of integers modulo p as well.
    We use the short Weierstrass form of representation.

    Attributes:
        p (int): the modulus of the ring
        Z_p (IntegerModRing): the ring modulo p over which the curve is defined
        a (IntegerMod_int): the `a` parameter of the curve
        b (IntegerMod_int): the `b` parameter of the curve
    """
    def __init__(self, a, b, p):
        self.p = p
        self.Z_p = Zmod(p)
        self.a = self.Z_p(a)
        self.b = self.Z_p(b)

    def is_singular(self) -> bool:
        """Check whether the curve is singular

        Returns:
            bool: True if the curve is singular (i.e. its discriminant is 0) and False otherwise
        """
        return 4 * self.a**3 + 27 * self.b**2 == 0

    def on_curve(self, x, y) -> bool:
        """Check whether a point of given (x,y) coordinates lays on the curve

        Returns:
            bool: True if the curve if the point is on the curve (i.e. its coordinates fulfill the
                curve equation over the base field) and False otherwise
        """
        x = self.Z_p(x)
        y = self.Z_p(y)
        return y**2 - x**3 - self.a * x - self.b == 0

    @property
    def infinity_point(self):
        """Get the point at infinity for the curve

        Returns:
            Point: the point at infinity for the curve
        """
        return PointInf(self)

    def __str__(self):
        return f'<Elliptic Curve over Z mod {p} with equation y^2 = x^3 + {a}x + {b}>'

    def __eq__(self, other: Self) -> bool:
        if not isinstance(other, Curve):
            return False
        return self.a == other.a and self.b == other.b and self.p == other.p

    def __contains__(self, item: "Point") -> bool:
        if not isinstance(item, Point):
            return False

        return self == item.curve and self.on_curve(item.x, item.y)

class Point:
    """A point over an elliptic curve

    Attributes:
        curve (Curve): the curve to which the point belongs
        x (IntegerMod_int): the x-coordinate of the point, belongs in Z mod p
        y (IntegerMod_int): the y-coordinate of the point, belongs in Z mod p
    """

    def __init__(self, curve, x, y):
        self.curve = curve
        self.x = curve.Z_p(x)
        self.y = curve.Z_p(y)

        if not self.curve.on_curve(self.x, self.y):
            warnings.warn(f'Point ({self.x}, {self.y}) is not on curve "{self.curve}"')

    def __str__(self):
        return f'({self.x}, {self.y})'

    def __eq__(self, other: Self) -> bool:
        if not isinstance(other, Point):
            return False

        return self.curve == other.curve and self.x == other.x and self.y == other.y

    def __neg__(self) -> Self:
        return Point(self.curve, self.x, -self.y)

    def _double(self) -> Self:
        _lambda = (3 * self.x**2 + self.curve.a) / (2 * self.y)
        x_r = _lambda**2 - 2*self.x
        y_r = -(self.y + _lambda * (x_r - self.x))
        return Point(self.curve, x_r, y_r)

    def __add__(self, other: Self):
        if isinstance(other, PointInf):
            return self

        if isinstance(other, Point):
            if self.x == other.x and self.y == other.y:
                return self._double()

            if self.x == other.x and self.y != other.y:
                return self.curve.infinity_point

            _lambda = (self.y - other.y) / (self.x - other.x)
            x_r = _lambda**2 - self.x - other.x
            y_r = -(self.y + _lambda * (x_r - self.x))
            return Point(self.curve, x_r, y_r)

        raise TypeError(f'Unsupported operand type(s) for point addition: {type(other)}')

    def __rmul__(self, other) -> Self:
        try:
            scalar = Integer(other)
        except:
            raise TypeError(f'Unsupported operand type(s) for scalar multiplication: {type(other)}')

        result = [PointInf(self.curve), self]

        # iterate over all bits of "scalar" starting by the MSB
        for bit in reversed(scalar.bits()):
            result[1 - bit] = result[1 - bit] + result[bit]
            result[bit] = result[bit] + result[bit]
        return result[0]

    def __mul__(self, other) -> Self:
        return self.__rmul__(other)

class PointInf(Point):
    """A special point on an elliptic curve that acts as the neutral element for addition

    Attributes:
        curve (Curve): the elliptic curve to which the point belongs
    """
    def __init__(self, curve):
        self.curve = curve

    def __eq__(self, other: Point):
        if not isinstance(other, PointInf):
            return False
        return self.curve == other.curve

    def __neg__(self):
        return self

    def __add__(self, other: Point):
        if isinstance(other, PointInf):
            return self
        if isinstance(other, Point):
            return other
        raise TypeError(f'Unsupported operand type(s) for point addition: expected Point, got {type(other)}')

    def scalar_multiply(self, scalar):
        return self

class ECDSA2_Params:
    """A container class for parameters that define an ECDSA^2 operation

    Attributes:
        curve (Curve): the elliptic curve on which the ECDSA^2 operations are done
        P (Point): the base point of the group
        q (Integer): the order of the base point
    """

    def __init__(self, a, b, p, P_x, P_y, q):
        self.curve = Curve(a, b, p)
        self.P = Point(self.curve, P_x, P_y)
        self.q = q

class ECDSA2():
    """A class that collects ECDSA^2 operations

    The values in `params` are expanded and saved as attributes for your convenience.

    Attributes:
        curve (Curve): the elliptic curve on which the ECDSA^2 operations are done
        p (Integer): the modulus of field of the elliptic curve `curve`
        P (Point): the base point of the group
        q (Integer): the order of the base point
        Z_q (IntegerModRing): the ring of integers mod q
    """

    def __init__(self, params):
        self.curve = params.curve
        self.p = params.curve.p
        self.P = params.P
        self.q = params.q
        self.Z_q = Zmod(self.q)

    def KeyGen(self) -> Tuple[IntegerMod_int, Point]:
        """Generates an ECDSA^2 key pair

        Returns:
            IntegerMod_int: the private key
            Point: the public key
        """
        x = 0
        while x == 0:
            x = secrets.randbelow(self.q)
        x = self.Z_q(x)
        Q = x * self.P
        return x, Q

    def Sign_FixedNonce(self, nonce: IntegerMod_int, privkey: IntegerMod_int, msg: str) -> Tuple[IntegerMod_int, IntegerMod_int]:
        """Computes an ECDSA^2 signature for a previously chosen nonce

        Args:
            nonce (IntegerMod_int): the nonce to be used for signing
            privkey (IntegerMod_int): the private key to be used for signing
            msg (str): the message to sign

        Returns:
            Tuple[IntegerMod_int, IntegerMod_int]: the tuple (r, s) of the signature
        """
        # FILL IN THIS METHOD
        h_as_bits = hash_message_to_bits(msg)
        h = self.Z_q(bits_to_int(h_as_bits, self.q))

        while True:
            r = self.Z_q((nonce * self.P).x)

            k_inv = inverse_mod(nonce, self.q)

            s = self.Z_q(k_inv * (h**2 + 1337 * privkey * r))

            if r != 0 and s != 0:
                break
            
        return (r, s)

    def Sign(self, privkey, msg) -> Tuple[IntegerMod_int, IntegerMod_int]:
        """Computes an ECDSA^2 signature for a randomly chosen nonce

        This method samples a nonce randomly and uses it to sign.

        Args:
            privkey (IntegerMod_int): the private key to be used for signing
            msg (str): the message to sign

        Returns:
            Tuple[IntegerMod_int, IntegerMod_int]: the tuple (r, s) of the signature
        """
        # FILL IN THIS METHOD
        h_as_bits = hash_message_to_bits(msg)
        h = self.Z_q(bits_to_int(h_as_bits, self.q))

        while True:
            k = self.Z_q.random_element()
            r = self.Z_q((k * self.P).x)

            k_inv = inverse_mod(k, self.q)

            s = self.Z_q(k_inv * (h**2 + 1337 * privkey * r))

            if r != 0 and s != 0:
                break
            
        return (r, s)

    def Verify(self, pubkey: Point, msg: str, r: IntegerMod_int, s: IntegerMod_int) -> bool:
        """Verifies an ECDSA^2 signature

        Args:
            pubkey (Point): the public key to be used for verification
            msg (str): the message over which the signature was computed
            r (IntegerMod_int): the first half of the signature
            s (IntegerMod_int): the second half of the signature

        Returns:
            bool: True if the signature verifies, False otherwise
        """
        # FILL IN THIS METHOD
        if (r > self.q - 1) or (r < 1) or (s > self.q - 1) or (s < 1):
            return False
    
        h_as_bits = hash_message_to_bits(msg)
        h = bits_to_int(h_as_bits, self.q)
        
        s_inv = inverse_mod(s, self.q)

        u1 = self.Z_q(s_inv * h**2)
        u2 = self.Z_q(s_inv * r * 1337)
        
        Z = u1 * self.P + u2 * pubkey
        
        return True if self.Z_q(Z.x) == r else False

if __name__ == "__main__":
    # A small test suite for verifying that everything works
    a   = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
    b   = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
    p   = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
    P_x = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
    P_y = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
    q   = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551

    nistp256_params = ECDSA2_Params(a, b, p, P_x, P_y, q)

    ecdsa2 = ECDSA2(nistp256_params)
    msg ="I can't not overthink it, it's impossible"

    sk, pk = ecdsa2.KeyGen()
    r, s = ecdsa2.Sign(sk, msg)
    assert ecdsa2.Verify(pk, msg, r, s)
