''' <MIT License>

 This code is a Mojo translation/rewrite by Aleksandr Zverianskii of csiphash and pysiphash  written by Marek Majkowski, which can be found at https://github.com/majek/csiphash/. The original MIT License terms apply:

 Copyright (c) 2013  Marek Majkowski <marek@popcount.org>

 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in
 all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 THE SOFTWARE.
 </MIT License>

 Original location:
    https://github.com/majek/csiphash/

 Solution inspired by code from:
    Samuel Neves (supercop/crypto_auth/siphash24/little)
    djb (supercop/crypto_auth/siphash24/little2)
    Jean-Philippe Aumasson (https://131002.net/siphash/siphash24.c)
'''

from builtin.string import ord

alias _zeros = String("\x00\x00\x00\x00\x00\x00\x00\x00")


fn rotate(x: UInt64, b: UInt64) -> UInt64:
    return ((x) << (b)) | ((x) >> (64 - (b)))


fn half_round(
    inout a: UInt64,
    inout b: UInt64,
    inout c: UInt64,
    inout d: UInt64,
    s: UInt64,
    t: UInt64,
):
    a += b
    c += d
    b = rotate(b, s) ^ a
    d = rotate(d, t) ^ c
    a = rotate(a, 32)


fn double_round(inout v0: UInt64, inout v1: UInt64, inout v2: UInt64, inout v3: UInt64):
    half_round(v0, v1, v2, v3, 13, 16)
    half_round(v2, v1, v0, v3, 17, 21)
    half_round(v0, v1, v2, v3, 13, 16)
    half_round(v2, v1, v0, v3, 17, 21)


fn str_to_uint64(s: String) -> UInt64:
    var val: Int = 0
    for i in range(1, len(s) + 1):
        val = val << 8
        val += ord(s[len(s) - i])
    return val

struct SipHash_2_4:
    var k0: UInt64
    var k1: UInt64
    var v0: UInt64
    var v1: UInt64
    var v2: UInt64
    var v3: UInt64
    var b: UInt64
    var s: String

    fn __init__(inout self, secret: String, s: String):
       self.k0 = str_to_uint64(secret[0:8])
       self.k1 = str_to_uint64(secret[8:16])
       self.v0 = self.k0 ^ 0x736F6D6570736575
       self.v1 = self.k1 ^ 0x646F72616E646F6D
       self.v2 = self.k0 ^ 0x6C7967656E657261
       self.v3 = self.k1 ^ 0x7465646279746573
       self.s = String("")
       self.b = 0
       self.update(s)
       

    fn update(inout self, s: String):
       self.s = self.s + s
       let lim = (len(s) // 8) * 8
       for off in range(0, lim, 8):
         let mi = str_to_uint64(s[off : off + 8])
         self.v3 ^= mi
         double_round(self.v0, self.v1, self.v2, self.v3)
         self.v0 ^= mi
       self.s = s[lim:]
       self.b += lim
       
    fn hash(inout self) -> UInt64:
      var v0: UInt64 = self.v0
      var v1: UInt64 = self.v1
      var v2: UInt64 = self.v2
      var v3: UInt64 = self.v3      
      let b: UInt64 = (((self.b + len(self.s)) & 0xFF) << 56) | str_to_uint64(
        (self.s + _zeros)[:8])
      v3 ^= b
      double_round(v0, v1, v2, v3)
      v0 ^= b
      v2 ^= 0xFF
      v3 ^= 0
      double_round(v0, v1, v2, v3)
      v0 ^= 0
      v3 ^= 0
      double_round(v0, v1, v2, v3)
      v0 ^= 0
      return v0 ^ v1 ^ v2 ^ v3
