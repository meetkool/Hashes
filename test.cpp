#include "hashes.h"
#include <iostream>

using namespace std;

int main() {
  cout << "       MD2: " << md2("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") << endl;
  cout << "       MD4: " << md4("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") << endl;
  cout << "       MD5: " << md5("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") << endl;
  cout << "      SHA0: " << sha0("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") << endl;
  cout << "      SHA1: " << sha1("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") << endl;
  cout << "    SHA224: " << sha224("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") << endl;
  cout << "    SHA256: " << sha256("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") << endl;
  cout << "    SHA384: " << sha384("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") << endl;
  cout << "    SHA512: " << sha512("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") << endl;
  cout << "SHA512/224: " << sha512_224("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") << endl;
  cout << "SHA512/256: " << sha512_256("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") << endl;

  return 0;
}
