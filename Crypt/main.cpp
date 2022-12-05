#include "OneTimePad.h"
#include "FourSquareCipher.h"
#include "XXTEA.h"
#include "SHA1.h"
#include "BMPEncrypter.h"


#include <iostream>

int main() {
	std::cout << std::boolalpha;

	auto start = std::chrono::high_resolution_clock::now();

	const std::string otp_file =
		R"(D:\Downloads\Fast.and.Furious.6.2013.EXTENDED.720p.BluRay.H264.AAC-RARBG\Fast.and.Furious.6.2013.EXTENDED.720p.BluRay.H264.AAC-RARBG.mp4)";
	const std::string otp_file_encrypted = otp_file + " encrypted";
	const std::string otp_file_decrypted = otp_file + " decrypted";

	const std::string otp_key_file = otp_file + " otp.key";

	//OneTimePad::encrypt(R"(D:\Desktop\dr dre.jpg)", R"(D:\Desktop\dr dre encrypted.jpg)", R"(D:\Desktop\otp.key)");
	//OneTimePad::decrypt(R"(D:\Desktop\dr dre encrypted.jpg)", R"(D:\Desktop\dr dre decrypted.jpg)", R"(D:\Desktop\otp.key)");

	//OneTimePad::encrypt(otp_file, otp_file_encrypted, otp_key_file);
	//OneTimePad::decrypt(otp_file_encrypted, otp_file_decrypted, otp_key_file);

	//auto end = std::chrono::high_resolution_clock::now();

	//std::cout << "Four square cipher time: " << std::chrono::duration_cast<std::chrono::seconds>(end - start);

	// FourSquareCipher::encrypt("D:\\Desktop\\a.txt", "D:\\Desktop\\fsc.txt");
	// FourSquareCipher::decrypt("D:\\Desktop\\fsc.txt", "D:\\Desktop\\b.txt");

	const std::string sha1_file = R"(D:\\Desktop\\a.txt)";

	std::cout << "Sha1: " << SHA1::hash(sha1_file) << std::endl << std::endl;

	//std::cout << Sha1::compare_files(R"(D:\\Desktop\\dr dre.jpg)", R"(D:\\Desktop\\dr dre decrypted.jpg)") << std::endl;

	//BmpEncrypter::encrypt_one_time_pad(R"(D:\Desktop\AM.bmp)", R"(D:\Desktop\AM encrypted.bmp)", R"(D:\Desktop\AM encrypted.key)");
	//BmpEncrypter::decrypt_one_time_pad(R"(D:\Desktop\AM encrypted.bmp)", R"(D:\Desktop\AM encrypted.key)", R"(D:\Desktop\AM decrypted.bmp)");

	//BmpEncrypter::open_file_with_default_program(R"(D:\Desktop\AM encrypted.bmp)");
	//BmpEncrypter::open_file_with_default_program(R"(D:\Desktop\AM decrypted.bmp)");

	//start = std::chrono::high_resolution_clock::now();

	//std::cout << Sha1::compare_files(R"(D:\Desktop\AM.bmp)", R"(D:\Desktop\AM decrypted.bmp)") << std::endl;

	//std::cout << Sha1::compare_files(otp_file, otp_file_encrypted) << std::endl;


	//end = std::chrono::high_resolution_clock::now();

	//std::cout << "SHA1: " << std::chrono::duration_cast<std::chrono::seconds>(end - start);

	XXTEA::encrypt(R"(D:\Desktop\b.txt)", R"(D:\Desktop\b encrypted.txt)", "123");
	XXTEA::decrypt(R"(D:\Desktop\b encrypted.txt)", R"(D:\Desktop\b decrypted.txt)", "123");
	std::cout << "Hash comparison: " << SHA1::compare_files(R"(D:\Desktop\b.txt)", R"(D:\Desktop\b decrypted.txt)") << std::endl;


	return 0;
}
