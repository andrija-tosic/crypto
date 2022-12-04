#pragma once
#include <cstdint>
#include <string>
#include <fstream>
#include <vector>
#include "OneTimePad.h"

class BmpEncrypter {
	static constexpr size_t BUF_SIZE = 4096;

	struct BmpFileHeader {
		uint8_t header[2];
		uint32_t size_bytes;
		uint16_t reserved1, reserved2;
		uint32_t starting_address;

		uint32_t dib_header_size;
		uint32_t width;
		uint32_t height;
		uint16_t planes, bit_count;
		uint32_t compression;
		uint32_t size_image;
		uint32_t x_pixels_per_meter;
		uint32_t y_pixels_per_meter;
		uint32_t clr_used;
		uint32_t clr_important;
	};

public:
	static void encrypt_one_time_pad(const std::string& in_file_path, const std::string& out_file_path, const std::string& out_pad_key_file_path);
	static void decrypt_one_time_pad(const std::string& in_file_path, const std::string& pad_key_file_path, const std::string& out_file_path);

	static void open_file_with_default_program(const std::string out_file_path);
};