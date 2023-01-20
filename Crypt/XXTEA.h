#pragma once
#include <cstdint>
#include <array>
#include <vector>
#include <fstream>
#include <cassert>
#include <iostream>

#define MX (((z>>5^y<<2) + (y>>3^z<<4)) ^ ((sum^y) + (key[(p&3)^e] ^ z)))

class XXTEA
{
	static constexpr size_t BLOCK_BUF_SIZE = 4096;

	static constexpr uint32_t DELTA = 0x9e3779b9;

	static void encrypt_block(std::vector<uint32_t>& v, const std::array<uint32_t, 4>& key);

	static void decrypt_block(std::vector<uint32_t>& v, const std::array<uint32_t, 4>& key);

	static constexpr std::size_t round_up_block(std::size_t num, std::size_t multiple);

	template <size_t n>
	static std::array<uint32_t, n> string_to_array_uint32(std::string s);

	static void byte_vec_to_vec_uint32(std::vector<uint32_t>& v, std::vector<uint8_t> b);

public:
	static void encrypt(const std::string& file_path, const std::string& out_file_path, const std::string& key);

	static void decrypt(const std::string& file_path, const std::string& out_file_path, const std::string& key);

};

