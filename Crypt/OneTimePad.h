#pragma once

#include <random>
#include <filesystem>
#include <string>
#include <fstream>

class OneTimePad {
protected:
	static constexpr size_t BUF_SIZE = 4096;

public:
	OneTimePad() = delete;
	~OneTimePad() = delete;
	OneTimePad(const OneTimePad&) = delete;
	OneTimePad(const OneTimePad&&) = delete;
	OneTimePad operator=(const OneTimePad&) = delete;
	OneTimePad operator=(const OneTimePad&&) = delete;

	static void encrypt(const std::string& file_path, const std::string& out_file_path, const std::string& out_pad_key_file_path);
	static void encrypt(std::basic_ifstream<uint8_t>& file, std::basic_ofstream<uint8_t>& outfile,
		std::basic_ofstream<uint8_t>& pad_key_file, size_t buffer_size);

	static void decrypt(const std::string& file_path, const std::string& out_file_path, const std::string& pad_key_file_path);
	static void decrypt(std::basic_ifstream<uint8_t>& file, std::basic_ofstream<uint8_t>& outfile, std::basic_ifstream<uint8_t>& pad_key_file,
		size_t buffer_size);
};
