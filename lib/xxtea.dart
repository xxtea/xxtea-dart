/**********************************************************\
|                                                          |
| xxtea.dart                                               |
|                                                          |
| XXTEA encryption algorithm library for Dart.             |
|                                                          |
| Encryption Algorithm Authors:                            |
|      David J. Wheeler                                    |
|      Roger M. Needham                                    |
|                                                          |
| Code Author: Ma Bingyao <mabingyao@gmail.com>            |
| LastModified: Oct 14, 2018                               |
|                                                          |
\**********************************************************/

library xxtea;

import "dart:convert";
import "dart:core";
import "dart:typed_data";

const XXTEA xxtea = const XXTEA();

Uint8List xxteaEncrypt(dynamic data, dynamic key) => xxtea.encrypt(data, key);
Uint8List xxteaDecrypt(dynamic data, dynamic key) => xxtea.decrypt(data, key);
String xxteaEncryptToString(dynamic data, dynamic key) => xxtea.encryptToString(data, key);
String xxteaDecryptToString(dynamic data, dynamic key) => xxtea.decryptToString(data, key);

class XXTEA {
  static const int _DELTA = 0x9E3779B9;

  const XXTEA();

  Uint8List _toUint8List(Uint32List v, bool includeLength) {
    int length = v.length;
    int n = length << 2;
    if (includeLength) {
      int m = v[length - 1];
      n -= 4;
      if ((m < n - 3) || (m > n)) {
        return null;
      }
      n = m;
    }
    Uint8List bytes = new Uint8List(n);
    for (int i = 0; i < n; ++i) {
      bytes[i] = v[i >> 2] >> ((i & 3) << 3);
    }
    return bytes;
  }

  Uint32List _toUint32List(Uint8List bytes, includeLength) {
    int length = bytes.length;
    int n = length >> 2;
    if ((length & 3) != 0) ++n;
    Uint32List v;
    if (includeLength) {
      v = new Uint32List(n + 1);
      v[n] = length;
    } else {
      v = new Uint32List(n);
    }
    for (int i = 0; i < length; ++i) {
      v[i >> 2] |= bytes[i] << ((i & 3) << 3);
    }
    return v;
  }

  int _mx(int sum, int y, int z, int p, int e, Uint32List k) {
    return ((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((sum ^ y) + (k[p & 3 ^ e] ^ z));
  }

  Uint8List _fixkey(Uint8List key) {
    if (key.length < 16) {
      Uint8List k = new Uint8List(16);
      k.setAll(0, key);
      return k;
    }
    return key;
  }

  int _int(int i) {
    return i & 0xFFFFFFFF;
  }

  Uint32List _encryptUint32List(Uint32List v, Uint32List k) {
    int length = v.length;
    int n = length - 1;
    int y, z, sum, e, p, q;
    z = v[n];
    sum = 0;
    for (q = 6 + (52 ~/ length); q > 0; --q) {
      sum = _int(sum + _DELTA);
      e = sum >> 2 & 3;
      for (p = 0; p < n; ++p) {
        y = v[p + 1];
        z = v[p] = _int(v[p] + _mx(sum, y, z, p, e, k));
      }
      y = v[0];
      z = v[n] = _int(v[n] + _mx(sum, y, z, p, e, k));
    }
    return v;
  }

  Uint32List _decryptUint32List(Uint32List v, Uint32List k) {

    int length = v.length;
    int n = length - 1;
    int y, z, sum, e, p, q;
    y = v[0];
    q = 6 + (52 ~/ length);
    for (sum = _int(q * _DELTA); sum != 0; sum = _int(sum - _DELTA)) {
        e = sum >> 2 & 3;
        for (p = n; p > 0; --p) {
            z = v[p - 1];
            y = v[p] = _int(v[p] - _mx(sum, y, z, p, e, k));
        }
        z = v[n];
        y = v[0] = _int(v[0] - _mx(sum, y, z, p, e, k));
    }
    return v;
  }

  Uint8List _toBytes(String str) {
    int n = str.length;
    // A single code unit uses at most 3 bytes. Two code units at most 4.
    Uint8List bytes = new Uint8List(n * 3);
    int length = 0;
    for (int i = 0; i < n; i++) {
      int codeUnit = str.codeUnitAt(i);
      if (codeUnit < 0x80) {
        bytes[length++] = codeUnit;
      } else if (codeUnit < 0x800) {
        bytes[length++] = 0xC0 | (codeUnit >> 6);
        bytes[length++] = 0x80 | (codeUnit & 0x3F);
      } else if (codeUnit < 0xD800 || codeUnit > 0xDfff) {
        bytes[length++] = 0xE0 | (codeUnit >> 12);
        bytes[length++] = 0x80 | ((codeUnit >> 6) & 0x3F);
        bytes[length++] = 0x80 | (codeUnit & 0x3F);
      } else {
        if (i + 1 < n) {
          int nextCodeUnit = str.codeUnitAt(i + 1);
          if (codeUnit < 0xDC00 && 0xDC00 <= nextCodeUnit && nextCodeUnit <= 0xDFFF) {
            int rune = (((codeUnit & 0x03FF) << 10) | (nextCodeUnit & 0x03FF)) + 0x010000;
            bytes[length++] = 0xF0 | ((rune >> 18) & 0x3F);
            bytes[length++] = 0x80 | ((rune >> 12) & 0x3F);
            bytes[length++] = 0x80 | ((rune >> 6) & 0x3F);
            bytes[length++] = 0x80 | (rune & 0x3F);
            i++;
            continue;
          }
        }
        throw new FormatException("Malformed string");
      }
    }
    return bytes.sublist(0, length);
  }

  Uint8List encrypt(dynamic data, dynamic key) {
    if (data is String) data = _toBytes(data);
    if (key is String) key = _toBytes(key);
    if (data == null || data.length == 0) {
      return data;
    }
    return _toUint8List(_encryptUint32List(_toUint32List(data, true), _toUint32List(_fixkey(key), false)), false);
  }

  String encryptToString(dynamic data, dynamic key) {
    return base64.encode(encrypt(data, key));
  }

  Uint8List decrypt(dynamic data, dynamic key) {
    if (data is String) data = base64.decode(data);
    if (key is String) key = _toBytes(key);
    if (data == null || data.length == 0) {
      return data;
    }
    return _toUint8List(_decryptUint32List(_toUint32List(data, false), _toUint32List(_fixkey(key), false)), true);
  }

  String decryptToString(dynamic data, dynamic key) {
    return utf8.decode(decrypt(data, key));
  }
}
