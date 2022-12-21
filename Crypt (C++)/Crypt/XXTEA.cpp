#include "XXTEA.h"
#include <filesystem>

void XXTEA::encrypt_block(std::vector<uint32_t>& v, const std::array<uint32_t, 4>& key) {
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

void XXTEA::decrypt_block(std::vector<uint32_t>& v, const std::array<uint32_t, 4>& key) {
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

template<size_t n>
std::array<uint32_t, n> XXTEA::string_to_array_uint32(std::string s) {
	constexpr size_t m = (sizeof(uint32_t) / sizeof(char));

	/* Apply padding if needed. */
	s.resize(n * m, 'X');

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


constexpr std::size_t XXTEA::round_up_block(std::size_t num, std::size_t multiple) {

	size_t remainder = num % multiple;
	if (remainder == 0) {
		return num;
	}

	return num + multiple - remainder;
}

void XXTEA::byte_vec_to_vec_uint32(std::vector<uint32_t>& v, std::vector<uint8_t> b) {
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

void XXTEA::encrypt(const std::string& file_path, const std::string& out_file_path, const std::string& key) {
	std::basic_ifstream<uint8_t> file(file_path, std::ios::in | std::ios::binary);
	std::basic_ofstream<uint8_t> outfile(out_file_path, std::ios::out | std::ios::binary);

	if (file.bad()) {
		throw std::exception("File error");
	}

	uintmax_t file_size = std::filesystem::file_size(file_path);

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

void XXTEA::decrypt(const std::string& file_path, const std::string& out_file_path, const std::string& key) {
	std::basic_ifstream<uint8_t> file(file_path, std::ios::in | std::ios::binary);
	std::basic_ofstream<uint8_t> outfile(out_file_path, std::ios::out | std::ios::binary);

	if (file.bad()) {
		throw std::exception("File error");
	}

	uintmax_t file_size = std::filesystem::file_size(file_path);

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
