# XXTEA for Dart

<a href="https://github.com/xxtea/">
    <img src="https://avatars1.githubusercontent.com/u/6683159?v=3&s=86" alt="XXTEA logo" title="XXTEA" align="right" />
</a>

[![Pub](https://img.shields.io/pub/v/xxtea.svg)](https://pub.dartlang.org/packages/xxtea)

## Introduction

XXTEA is a fast and secure encryption algorithm. This is a XXTEA library for Dart.

It is different from the original XXTEA encryption algorithm. It encrypts and decrypts String/Uint8List instead of uint32 array, and the key is also String/Uint8List.

## Usage

```dart
import 'package:xxtea/xxtea.dart';

String str = "Hello World! 你好，中国🇨🇳！";
String key = "1234567890";
String encrypt_data = XXTEA.encryptToString(str, key);
print(encrypt_data)
String decrypt_data = XXTEA.decryptToString(encrypt_data, key);
print(str == encrypt_data)
```
