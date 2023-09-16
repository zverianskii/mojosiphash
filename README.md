mojosiphash
====

A Mojo implementation of [SipHash-2-4](https://131002.net/siphash/),
a fast short-input
[PRF](https://en.wikipedia.org/wiki/Pseudorandom_function) with a
128-bit key and 64-bit output.

Extract from the description:

    SipHash is a family of pseudorandom functions (a.k.a. keyed hash
    functions) optimized for speed on short messages.

    Target applications include network traffic authentication and defense
    against hash-flooding DoS attacks.

    SipHash is secure, fast, and simple (for real):
    * SipHash is simpler and faster than previous cryptographic algorithms
      (e.g. MACs based on universal hashing)
    * SipHash is competitive in performance with insecure
      non-cryptographic algorithms (e.g. MurmurHash)
    * We propose that hash tables switch to SipHash as a hash
      function. Users of SipHash already include OpenDNS, Perl 5, Ruby, or
      Rust.


```mojo
from mojosiphash import siphash

fn main():
    let key = String("0123456789ABCDEF")
    let s = String("a")
    var sip = siphash.SipHash_2_4(key, s)
    let res: UInt64 = sip.hash()
    print(res) # 12398370950267227270
```
