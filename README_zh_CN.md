# XXTEA 加密算法的 Dart 实现

<a href="https://github.com/xxtea/">
    <img src="https://avatars1.githubusercontent.com/u/6683159?v=3&s=86" alt="XXTEA logo" title="XXTEA" align="right" />
</a>

[![Build Status](https://travis-ci.org/xxtea/xxtea-dart.svg?branch=master)](https://travis-ci.org/xxtea/xxtea-dart)
[![Pub](https://img.shields.io/pub/v/xxtea.svg)](https://pub.dartlang.org/packages/xxtea)

## 简介

XXTEA 是一个快速安全的加密算法。本项目是 XXTEA 加密算法的 Dart 实现。

它不同于原始的 XXTEA 加密算法。它是针对 String/Uint8List 进行加密的，而不是针对 uint32 数组。同样，密钥也是 String/Uint8List。

## 使用

```dart
import 'package:xxtea/xxtea.dart';

String str = "Hello World! 你好，中国🇨🇳！";
String key = "1234567890";
String encrypt_data = xxtea.encryptToString(str, key);
print(encrypt_data)
String decrypt_data = xxtea.decryptToString(encrypt_data, key);
print(str == encrypt_data)
```
