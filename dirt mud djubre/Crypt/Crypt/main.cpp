#include "FourSquareCipher.h"
#include "OneTimePad.h"

int main() {

	OneTimePad::Encrypt("D:\\Desktop\\dr dre.jpg", "D:\\Desktop\\dr dre encrypted.jpg", "D:\\Desktop\\otp.key");
	OneTimePad::Decrypt("D:\\Desktop\\dr dre encrypted.jpg", "D:\\Desktop\\dr dre decrypted.jpg", "D:\\Desktop\\otp.key");

	FourSquareCipher::Encrypt("D:\\Desktop\\a.txt", "D:\\Desktop\\fsc.txt");
	FourSquareCipher::Decrypt("D:\\Desktop\\fsc.txt", "D:\\Desktop\\b.txt");

	return 0;
}