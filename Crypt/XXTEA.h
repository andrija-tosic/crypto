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

	static void encrypt_block(std::vector<uint32_t>& v, const std::array<uint32_t, 4>& key) {
		if (v.empty()) {
			return;
		}
		size_t n = v.size();
		uint32_t y, z, sum;
		unsigned p, rounds, e;

		rounds = 6 + 52 / n;
		sum = 0;
		z = v[n - 1];
		do {
			sum += DELTA;
			e = (sum >> 2) & 3;
			for (p = 0; p < n - 1; p++) {
				y = v[p + 1];
				v[p] += MX;
				z = v[p];
			}
			y = v[0];
			v[n - 1] += MX;
			z = v[n - 1];
		} while (--rounds);
	}

	static void decrypt_block(std::vector<uint32_t>& v, const std::array<uint32_t, 4>& key) {
		if (v.empty()) {
			return;
		}
		uint32_t n = (uint32_t)v.size();
		uint32_t y, z, sum;
		unsigned p, rounds, e;

		rounds = 6 + 52 / n;
		sum = rounds * DELTA;
		y = v[0];
		do {
			e = (sum >> 2) & 3;
			for (p = n - 1; p > 0; p--) {
				z = v[p - 1];
				y = v[p] -= MX;
			}
			z = v[n - 1];
			y = v[0] -= MX;
			sum -= DELTA;
		} while (--rounds);
	}

	static constexpr std::size_t round_up_block(std::size_t num, std::size_t multiple) {

		size_t remainder = num % multiple;
		if (remainder == 0) {
			return num;
		}

		return num + multiple - remainder;
	}

	template <size_t n>
	static std::array<uint32_t, n> string_to_array_uint32(std::string s) {
		constexpr size_t m = (sizeof(uint32_t) / sizeof(char));

		/* Apply padding if needed. */
		s.resize(n*m, 'X');

		std::cout << "Key: " << s << std::endl;

		std::array<uint32_t, n> arr{};
		for (size_t i = 0; i < n; i++) {
			arr[i] = (s[i * m + 3])
				| (s[i * m + 2] << 8)
				| (s[i * m + 1] << 16)
				| (s[i * m] << 24);
		}
		return arr;
	}

	static void byte_vec_to_vec_uint32(std::vector<uint32_t>& v, std::vector<uint8_t> b) {
		constexpr size_t multiple = sizeof(uint32_t) / sizeof(char);
		b.resize(XXTEA::round_up_block(b.size(), multiple));
		v.resize(b.size() / 4);

		for (size_t i = 0; i < b.size() / 4; i++) {
			v[i] = (b[i * 4 + 3])
				| (b[i * 4 + 2] << 8)
				| (b[i * 4 + 1] << 16)
				| (b[i * 4] << 24);
		}
	}

public:
	static void encrypt(const std::string& file_path, const std::string& out_file_path, const std::string& key) {
		std::basic_ifstream<uint8_t> file(file_path, std::ios::in | std::ios::binary);
		std::basic_ofstream<uint8_t> outfile(out_file_path, std::ios::out | std::ios::binary);

		if (file.bad()) {
			throw std::exception("File error");
		}

		file.ignore(std::numeric_limits<std::streamsize>::max());
		std::streamsize file_size = file.gcount();
		file.clear();
		file.seekg(0, std::ios_base::beg);

		size_t buffer_size = std::min((size_t)file_size, XXTEA::BLOCK_BUF_SIZE);

		if (file.bad()) {
			throw std::exception("File error");
		}

		std::vector<uint8_t> out_buf(buffer_size);
		std::vector<uint8_t> buf(buffer_size);

		const std::array<uint32_t, 4> key_as_arr = XXTEA::string_to_array_uint32<4>(key);

		std::vector<uint32_t> v{};

		while (file.good()) {
			file.read(buf.data(), buffer_size);

			std::streamsize c = file.gcount();


			if (file.gcount() == 0) break;

			/* If there's less than buffer_size bytes left of file. */
			if ((size_t)file.gcount() < buffer_size) {
				buffer_size = file.gcount();

				buf.resize(buffer_size);
				out_buf.resize(buffer_size);
			}
			std::cout << buf.data() << std::endl;

			XXTEA::byte_vec_to_vec_uint32(v, buf);

			for (auto& x : v) {
				printf("%c", x);
			}
			std::cout << std::endl << std::endl;

			XXTEA::encrypt_block(v, key_as_arr);

			for (auto& x : v) {
				printf("%c", x);
			}
			std::cout << std::endl;

			outfile.write((uint8_t*)v.data(), buffer_size);
		}

		file.close();
		outfile.close();
	}

	static void decrypt(const std::string& file_path, const std::string& out_file_path, const std::string& key) {
		std::basic_ifstream<uint8_t> file(file_path, std::ios::in | std::ios::binary);
		std::basic_ofstream<uint8_t> outfile(out_file_path, std::ios::out | std::ios::binary);

		if (file.bad()) {
			throw std::exception("File error");
		}

		file.ignore(std::numeric_limits<std::streamsize>::max());
		std::streamsize file_size = file.gcount();
		file.clear();
		file.seekg(0, std::ios_base::beg);

		size_t buffer_size = std::min((size_t)file_size, XXTEA::BLOCK_BUF_SIZE);

		if (file.bad()) {
			throw std::exception("File error");
		}

		std::vector<uint8_t> out_buf(buffer_size);
		std::vector<uint8_t> buf(buffer_size);

		const std::array<uint32_t, 4> key_as_arr = XXTEA::string_to_array_uint32<4>(key);

		std::vector<uint32_t> v{};

		while (file.good()) {
			file.read(buf.data(), buffer_size);

			std::streamsize c = file.gcount();

			if (file.gcount() == 0) break;

			/* If there's less than buffer_size bytes left of file. */
			if ((size_t)file.gcount() < buffer_size) {
				buffer_size = file.gcount();

				buf.resize(buffer_size);
				out_buf.resize(buffer_size);
			}

			XXTEA::byte_vec_to_vec_uint32(v, buf);

			XXTEA::decrypt_block(v, key_as_arr);

			outfile.write((uint8_t*)v.data(), buffer_size);
		}

		file.close();
		outfile.close();
	}

};
