library xxtea_test;

import "package:test/test.dart";
import 'package:xxtea/xxtea.dart';

void main() {
  test('XXTEA encrypt and decrypt.', () {
    String str = "Hello World! 你好，中国🇨🇳！";
    String key = "1234567890";
    String encrypt_data = xxtea.encryptToString(str, key);
    expect(encrypt_data, equals("D4t0rVXUDl3bnWdERhqJmFIanfn/6zAxAY9jD6n9MSMQNoD8TOS4rHHcGuE="));
    String decrypt_data = xxtea.decryptToString(encrypt_data, key);
    expect(decrypt_data, equals(str));
  });
}
