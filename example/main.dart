library xxtea_test;

import 'package:xxtea/xxtea.dart';

void main() {
  String str = "Hello World! 你好，中国🇨🇳！";
  String key = "1234567890";
  String? encrypt_data = xxtea.encryptToString(str, key);
  print(encrypt_data);
  String? decrypt_data = xxtea.decryptToString(encrypt_data, key);
  print(decrypt_data);
}
