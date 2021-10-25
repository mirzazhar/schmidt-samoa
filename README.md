# Schmidt-Samoa Cryptosystem
This package is implemented according to the pseudo-code and mathematical notations of the following algorithms of the Schmidt-Samoa cryptosystem:
 - Key Generation
 - Encryption
 - Decryption


Schmidt-Samoa has [multiplicative homomorphic encryption property](https://eprint.iacr.org/2005/278.pdf) and is an example of Partially Homomorphic Encryption (PHE). Therefore, the multiplication of ciphers results in the product of original numbers.

Moreover, it also supports the following PHE functions:
- Homomorphic Encryption over two ciphers
- Homomorphic Encryption over multiple ciphers


## Installation
```sh
go get -u github.com/mirzazhar/schmidt-samoa
```
## Warning
This package is intendedly designed for education purposes. Of course, it may contain bugs and needs several improvements. Therefore, this package should not be used for production purposes.
## Usage & Examples
## LICENSE
MIT License
## References
1. https://en.wikipedia.org/wiki/Schmidt-Samoa_cryptosystem
2. https://eprint.iacr.org/2005/278.pdf
