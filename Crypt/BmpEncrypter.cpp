#include "BMPEncrypter.h"
#include "windows.h"
#undef max
#undef min

void BMPEncrypter::encrypt_one_time_pad(const std::string& in_file_path, const std::string& out_file_path, const std::string& out_pad_key_file_path) {
	std::basic_ifstream<uint8_t> file(in_file_path, std::ios::in | std::ios::binary);
	std::basic_ofstream<uint8_t> out_file(out_file_path, std::ios::out | std::ios::binary);
	std::basic_ofstream<uint8_t> out_pad_key_file(out_pad_key_file_path, std::ios::out | std::ios::binary);

	if (file.bad() || out_file.bad()) {
		throw std::exception("File error");
	}

	file.ignore(std::numeric_limits<std::streamsize>::max());
	std::streamsize file_size = file.gcount();
	file.clear();
	file.seekg(0, std::ios_base::beg);

	size_t buffer_size = std::min((size_t)file_size, BUF_SIZE);

	std::vector<uint8_t> buf(buffer_size);

	BmpFileHeader header{};
	file.read(reinterpret_cast<uint8_t*>(&header), sizeof(BmpFileHeader));
	out_file.write(reinterpret_cast<uint8_t*>(&header), sizeof(BmpFileHeader));

	OneTimePad::encrypt(file, out_file, out_pad_key_file, buffer_size);
}

void BMPEncrypter::decrypt_one_time_pad(const std::string& in_file_path, const std::string& pad_key_file_path, const std::string& out_file_path) {
	std::basic_ifstream<uint8_t> file(in_file_path, std::ios::in | std::ios::binary);
	std::basic_ofstream<uint8_t> out_file(out_file_path, std::ios::out | std::ios::binary);
	std::basic_ifstream<uint8_t> pad_key_file(pad_key_file_path, std::ios::in | std::ios::binary);

	if (file.bad() || out_file.bad()) {
		throw std::exception("File error");
	}

	file.ignore(std::numeric_limits<std::streamsize>::max());
	std::streamsize file_size = file.gcount();
	file.clear();
	file.seekg(0, std::ios_base::beg);

	size_t buffer_size = std::min((size_t)file_size, BUF_SIZE);

	std::vector<uint8_t> buf(buffer_size);

	BmpFileHeader header{};
	file.read((uint8_t*)&header, sizeof(BmpFileHeader));
	out_file.write((uint8_t*)&header, sizeof(BmpFileHeader));

	OneTimePad::decrypt(file, out_file, pad_key_file, buffer_size);
}

void BMPEncrypter::open_file_with_default_program(const std::string out_file_path) {
	wchar_t wtext[256];
	size_t t = 256;
	mbstowcs_s(&t, wtext, out_file_path.c_str(), strlen(out_file_path.c_str()) + 1);//Plus null
	LPWSTR ptr = wtext;
	ShellExecuteW(NULL, NULL, wtext, NULL, NULL, SW_SHOW);
}
