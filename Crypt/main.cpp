#include "OneTimePad.h"
#include "FourSquareCipher.h"
#include "XXTEA.h"
#include "SHA1.h"
#include "BMPEncrypter.h"

#include <iostream>

void test_otp(const std::string& file, const std::string& file_encrypted, const std::string& file_decrypted,
	const std::string& key_file) {
	auto start = std::chrono::high_resolution_clock::now();

	OneTimePad::encrypt(file, file_encrypted, key_file);
	OneTimePad::decrypt(file_encrypted, file_decrypted, key_file);

	auto end = std::chrono::high_resolution_clock::now();

	std::cout << "OTP time taken: " << std::chrono::duration_cast<std::chrono::seconds>(end - start) << std::endl;
	std::cout << "OTP Hashes match: " << SHA1::compare_files(file, file_decrypted) << std::endl;
}

void test_fcs(const std::string& file, const std::string& file_encrypted, const std::string& file_decrypted, const std::string& key1, const std::string& key2) {
	auto start = std::chrono::high_resolution_clock::now();
	
	FourSquareCipher::encrypt(file, file_encrypted, key1, key2);
	FourSquareCipher::decrypt(file_encrypted, file_decrypted, key1, key2);

	auto end = std::chrono::high_resolution_clock::now();

	std::cout << "FCS time taken: " << std::chrono::duration_cast<std::chrono::seconds>(end - start) << std::endl;
	std::cout << "FCS Hashes match: " << SHA1::compare_files(file, file_decrypted) << std::endl;
}

void test_bmp_otp(const std::string& file, const std::string& file_encrypted, const std::string& file_decrypted,
	const std::string& key_file) {

	auto start = std::chrono::high_resolution_clock::now();

	BMPEncrypter::encrypt_one_time_pad(file, file_encrypted, key_file);
	BMPEncrypter::decrypt_one_time_pad(file_encrypted, key_file, file_decrypted);

	auto end = std::chrono::high_resolution_clock::now();

	std::cout << "BMP OTP time taken: " << std::chrono::duration_cast<std::chrono::seconds>(end - start) << std::endl;
	std::cout << "BMP OTP Hashes match: " << SHA1::compare_files(file, file_decrypted) << std::endl;

	BMPEncrypter::open_file_with_default_program(file_encrypted);
	BMPEncrypter::open_file_with_default_program(file_decrypted);
}

void test_xxtea(const std::string& file, const std::string& file_encrypted, const std::string& file_decrypted, const std::string& key) {
	XXTEA::encrypt(file, file_encrypted, key);
	XXTEA::decrypt(file_encrypted, file_decrypted, key);
}

int main() {
	std::cout << std::boolalpha;



	return 0;
}
