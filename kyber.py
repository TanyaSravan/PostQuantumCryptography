import os
from hashlib import sha3_256, sha3_512, shake_128, shake_256
from polynomials import *
from modules import *
from ntt_helper import NTTHelperKyber
from DRBG import AES256_CTR_DRBG


#Default params for different kyber security levels

DEFAULT_PARAMS = {
    "kyber_512": {
        "n": 256,
        "k": 2,
        "q": 3329,
        "eta_1": 3,
        "eta_2": 2,
        "du": 10,
        "dv": 4,
    },
    "kyber_768": {
        "n": 256,
        "k": 3,
        "q": 3329,
        "eta_1": 2,
        "eta_2": 2,
        "du": 10,
        "dv": 4,
    },
    "kyber_1024": {
        "n": 256,
        "k": 4,
        "q": 3329,
        "eta_1": 2,
        "eta_2": 2,
        "du": 11,
        "dv": 5,
    }
}


class Kyber:
    def __init__(self, params):
        self.n = params["n"]
        self.k = params["k"]
        self.q = params["q"]
        self.eta_1 = params["eta_1"]
        self.eta_2 = params["eta_2"]
        self.du = params["du"]
        self.dv = params["dv"]

        self.poly_ring = PolynomialRing(self.q, self.n, ntt_helper=NTTHelperKyber)
        self.module = Module(self.poly_ring)

        self.drbg = None
        self.random_bytes_func = os.urandom

    def set_drbg_seed(self, seed):
        self.drbg = AES256_CTR_DRBG(seed)
        self.random_bytes_func = self.drbg.random_bytes

    @staticmethod
    def _extendable_output_function(input32, a, b, length):
        input_bytes = input32 + a + b
        if len(input_bytes) != 34:
            raise ValueError(f"Input bytes should be one 32 byte array and 2 single bytes.")
        return shake_128(input_bytes).digest(length)

    @staticmethod
    def _hash(input_bytes):
        return sha3_256(input_bytes).digest()

    @staticmethod
    def _generate_hash(input_bytes):
        output = sha3_512(input_bytes).digest()
        return output[:32], output[32:]

    @staticmethod
    def _pseudo_random_function(s, b, length):
        input_bytes = s + b
        if len(input_bytes) != 33:
            raise ValueError(f"Input bytes should be one 32 byte array and one single byte.")
        return shake_256(input_bytes).digest(length)

    @staticmethod
    def _key_derivation_function(input_bytes, length):
        return shake_256(input_bytes).digest(length)

    def _generate_error_vector(self, seed, eta, counter, is_ntt=False):
        elements = []
        for i in range(self.k):
            input_bytes = self._pseudo_random_function(seed, bytes([counter]), 64 * eta)
            poly = self.poly_ring.cbd(input_bytes, eta, is_ntt=is_ntt)
            elements.append(poly)
            counter = counter + 1
        vector = self.module(elements).transpose()
        return vector, counter

    def _generate_matrix_from_seed(self, rho, transpose=False, is_ntt=False):
        matrix = []
        for i in range(self.k):
            row = []
            for j in range(self.k):
                if transpose:
                    input_bytes = self._extendable_output_function(rho, bytes([i]), bytes([j]), 3 * self.poly_ring.n)
                else:
                    input_bytes = self._extendable_output_function(rho, bytes([j]), bytes([i]), 3 * self.poly_ring.n)
                aij = self.poly_ring.parse(input_bytes, is_ntt=is_ntt)
                row.append(aij)
            matrix.append(row)
        return self.module(matrix)

    def _cpapke_keygen(self):
        random_value = self.random_bytes_func(32)
        rho, sigma = self._generate_hash(random_value)
        counter = 0

        matrix_A = self._generate_matrix_from_seed(rho, is_ntt=True)

        s, counter = self._generate_error_vector(sigma, self.eta_1, counter)
        s.to_ntt()

        e, counter = self._generate_error_vector(sigma, self.eta_1, counter)
        e.to_ntt()

        t = (matrix_A @ s).to_montgomery() + e

        t.reduce_coefficents()
        s.reduce_coefficents()

        pk = t.encode(l=12) + rho
        sk = s.encode(l=12)
        return pk, sk

    def _cpapke_enc(self, pk, message, coins):
        counter = 0
        rho = pk[-32:]

        t = self.module.decode(pk, 1, self.k, l=12, is_ntt=True)

        message_poly = self.poly_ring.decode(message, l=1).decompress(1)

        At = self._generate_matrix_from_seed(rho, transpose=True, is_ntt=True)

        r, counter = self._generate_error_vector(coins, self.eta_1, counter)
        r.to_ntt()

        e1, counter = self._generate_error_vector(coins, self.eta_2, counter)

        input_bytes = self._pseudo_random_function(coins, bytes([counter]), 64 * self.eta_2)
        e2 = self.poly_ring.cbd(input_bytes, self.eta_2)

        u = (At @ r).from_ntt() + e1
        v = (t @ r)[0][0].from_ntt()
        v = v + e2 + message_poly

        c1 = u.compress(self.du).encode(l=self.du)
        c2 = v.compress(self.dv).encode(l=self.dv)

        return c1 + c2

    def _cpapke_dec(self, sk, ciphertext):
        index = self.du * self.k * self.poly_ring.n // 8
        c2 = ciphertext[index:]

        u = self.module.decode(ciphertext, self.k, 1, l=self.du).decompress(self.du)
        u.to_ntt()

        v = self.poly_ring.decode(c2, l=self.dv).decompress(self.dv)

        st = self.module.decode(sk, 1, self.k, l=12, is_ntt=True)

        message_poly = (st @ u)[0][0].from_ntt()
        message_poly = v - message_poly

        return message_poly.compress(1).encode(l=1)

    def keygen(self):
        pk, _sk = self._cpapke_keygen()
        z = self.random_bytes_func(32)

        sk = _sk + pk + self._hash(pk) + z
        return pk, sk

    def enc(self, pk, key_length=32):
        message = self.random_bytes_func(32)
        message_hash = self._hash(message)
        Kbar, r = self._generate_hash(message_hash + self._hash(pk))
        ciphertext = self._cpapke_enc(pk, message_hash, r)
        K = self._key_derivation_function(Kbar + self._hash(ciphertext), key_length)
        return ciphertext, K

    def dec(self, ciphertext, sk, key_length=32):
        index = 12 * self.k * self.poly_ring.n // 8
        _sk = sk[:index]
        pk = sk[index:-64]
        hpk = sk[-64:-32]
        z = sk[-32:]

        decrypted_message = self._cpapke_dec(_sk, ciphertext)

        _Kbar, _r = self._generate_hash(decrypted_message + hpk)
        _c = self._cpapke_enc(pk, decrypted_message, _r)

        if ciphertext == _c:
            return self._key_derivation_function(_Kbar + self._hash(ciphertext), key_length)
        return self._key_derivation_function(z + self._hash(ciphertext), key_length)


Kyber512 = Kyber(DEFAULT_PARAMS["kyber_512"])
Kyber768 = Kyber(DEFAULT_PARAMS["kyber_768"])
Kyber1024 = Kyber(DEFAULT_PARAMS["kyber_1024"])
