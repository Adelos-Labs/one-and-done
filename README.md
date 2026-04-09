# One-and-Done

A practical [one-time pad](https://en.wikipedia.org/wiki/One-time_pad) implementation providing:

- [Information-theoretic security](https://en.wikipedia.org/wiki/Information-theoretic_security)
- A Carter-Wegman Message Authentication Code (MAC) to verify the message hasn't been tampered with or forged without compromising information-theoretic security (you can read on the underlying maths [here](https://eng.libretexts.org/Under_Construction/Book%3A_The_Joy_of_Cryptography_(Rosulek)/13%3A_Authenticated_Encryption_and_AEAD/13.03%3A_Carter-Wegman_MACs))
- Metadata to support seamless key transitions and out-of-order messages

## Install

```bash
go install ./cmd/otp
```

Make sure `$(go env GOPATH)/bin` is in your `PATH`.

## Usage

Each party in a conversation needs their own key file, and the other party needs a copy of it. For example, if Alice and Bob want to communicate:

- `alice.key` — Alice uses this to encipher; Bob uses his copy to decipher
- `bob.key` — Bob uses this to encipher; Alice uses her copy to decipher

Both key files must be securely shared in advance (e.g. in person via USB drive).

```bash
# Set up directories for each party
mkdir alice bob

# Generate a key for each direction
otp genkey alice/alice.key 1024
otp genkey bob/bob.key 1024

# Securely share copies (in practice, via USB drive — not over the network)
cp alice/alice.key bob/alice.key
cp bob/bob.key alice/bob.key

# Alice sends a message
otp encipher alice/alice.key "hello bob"
# Bob deciphers it with his copy
otp decipher bob/alice.key <envelope>

# Bob replies
otp encipher bob/bob.key "hi alice"
# Alice deciphers it with her copy
otp decipher alice/bob.key <envelope>

rm -rf alice/ bob/
```

Key bytes are consumed with each operation. Do not reuse key material or run concurrent operations against the same key file.

