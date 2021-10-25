package schmidtsamoa

import (
	"crypto/rand"
	"errors"
	"io"
	"math/big"
)

var one = big.NewInt(1)
var ErrLargeMessage = errors.New("schmidt-samoa: message is larger than Schmidt Samoa public key size")
var ErrLargeCipher = errors.New("schmidt-samoa: cipher is larger than Schmidt Samoa public key size")

// GenerateKey generates Schmidt-Samoa key according to the given bit-size.
func GenerateKey(random io.Reader, bits int) (*PrivateKey, error) {
	// prime number p
	p, err := rand.Prime(random, bits/2)
	if err != nil {
		return nil, err
	}

	// prime number q
	q, err := rand.Prime(random, bits/2)
	if err != nil {
		return nil, err
	}

	// psquare = p * p
	psquare := new(big.Int).Mul(p, p)

	// n = psquare * q
	n := new(big.Int).Mul(psquare, q)
	pq := new(big.Int).Mul(p, q)

	// l = lcm (p-1, q-1)
	lcm := new(big.Int).Mul(
		new(big.Int).Sub(p, one),
		new(big.Int).Sub(q, one),
	)

	// n^(-1) mod [lcm (p-1, q-1)]
	d := new(big.Int).ModInverse(n, lcm)

	return &PrivateKey{
		PublicKey: PublicKey{
			N: n,
		},
		L:  lcm,
		D:  d,
		PQ: pq,
	}, nil
}

// PrivateKey represents a Schmidt-Samoa private key.
type PrivateKey struct {
	PublicKey
	L  *big.Int
	D  *big.Int
	PQ *big.Int
}

// PublicKey represents Schmidt-Samoa public key.
type PublicKey struct {
	N *big.Int // modulus N
}

// Encrypt encrypts a plain text represented as a byte array. It returns
// an error if plain text value is larger than modulus N of Public key.
func (pub *PublicKey) Encrypt(plainText []byte) ([]byte, error) {
	m := new(big.Int).SetBytes(plainText)
	if m.Cmp(pub.N) == 1 { //  m < N
		return nil, ErrLargeMessage
	}

	// c=m^N mod N
	c := new(big.Int).Mod(
		new(big.Int).Exp(m, pub.N, pub.N),
		pub.N,
	)
	return c.Bytes(), nil
}

// Decrypt decrypts the passed cipher text. It returns
// an error if cipher text value is larger than modulus N of Public key.
func (priv *PrivateKey) Decrypt(cipherText []byte) ([]byte, error) {
	c := new(big.Int).SetBytes(cipherText)
	if c.Cmp(priv.N) == 1 { // c < N
		return nil, ErrLargeCipher
	}

	// m = c^d mod pq
	m := new(big.Int).Mod(
		new(big.Int).Exp(c, priv.D, priv.PQ),
		priv.PQ,
	)
	return m.Bytes(), nil
}

// HomomorphicEncTwo performs homomorphic operation over two chiphers.
// Schmidt-Samoa has multiplicative homomorphic property, so resultant cipher
// contains the product of two numbers.
func (pub *PublicKey) HomomorphicEncTwo(c1, c2 []byte) ([]byte, error) {
	cipherA := new(big.Int).SetBytes(c1)
	cipherB := new(big.Int).SetBytes(c2)
	if cipherA.Cmp(pub.N) == 1 && cipherB.Cmp(pub.N) == 1 { // c < N
		return nil, ErrLargeCipher
	}

	// C = c1*c2 mod N
	C := new(big.Int).Mod(
		new(big.Int).Mul(cipherA, cipherB),
		pub.N,
	)
	return C.Bytes(), nil
}

// HommorphicEncMultiple performs homomorphic operation over two chiphers.
// Schmidt-Samoa has multiplicative homomorphic property, so resultant cipher
// contains the product of multiple numbers.
func (pub *PublicKey) HommorphicEncMultiple(ciphers ...[]byte) ([]byte, error) {
	C := one

	for i := 0; i < len(ciphers); i++ {
		cipher := new(big.Int).SetBytes(ciphers[i])
		if cipher.Cmp(pub.N) == 1 { // c < N
			return nil, ErrLargeCipher
		}
		// C = c1*c2*c3...cn mod N
		C = new(big.Int).Mod(
			new(big.Int).Mul(C, cipher),
			pub.N,
		)
	}
	return C.Bytes(), nil
}
