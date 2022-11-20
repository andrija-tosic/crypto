#include "OneTimePad.h"

int main() {

	OneTimePad::Encrypt("D:\\Desktop\\dr dre.jpg", "D:\\Desktop\\dr dre encrypted.jpg", "D:\\Desktop\\otp.key");

	OneTimePad::Decrypt("D:\\Desktop\\dr dre encrypted.jpg", "D:\\Desktop\\dr dre decrypted.jpg", "D:\\Desktop\\otp.key");

	return 0;
}