#include "OneTimePad.h"
#include "RNG.h"

void OneTimePad::encrypt(const std::string& file_path, const std::string& out_file_path, const std::string& pad_key_file_path) {
	std::basic_ifstream<uint8_t> file(file_path, std::ios::in | std::ios::binary);
	std::basic_ofstream<uint8_t> outfile(out_file_path, std::ios::out | std::ios::binary);
	std::basic_ofstream<uint8_t> pad_key_file(out_file_path, std::ios::out | std::ios::binary);

	if (file.bad()) {
		throw std::exception("File error");
	}

	file.ignore(std::numeric_limits<std::streamsize>::max());
	std::streamsize file_size = file.gcount();
	file.clear();
	file.seekg(0, std::ios_base::beg);

	size_t buffer_size = std::min((size_t)file_size, OneTimePad::BUF_SIZE);

	OneTimePad::encrypt(file, outfile, pad_key_file, buffer_size);
}

void OneTimePad::encrypt(std::basic_ifstream<uint8_t>& file, std::basic_ofstream<uint8_t>& outfile, 
	std::basic_ofstream<uint8_t>& pad_key_file, size_t buffer_size) {
	
	if (file.bad() || pad_key_file.bad()) {
		throw std::exception("File error");
	}

	std::vector<uint8_t> pad(buffer_size);
	std::vector<uint8_t> out_buf(buffer_size);
	std::vector<uint8_t> buf(buffer_size);

	RNG rng;

	while (file.good()) {
		file.read(buf.data(), buffer_size);

		std::streamsize c = file.gcount();

		if (file.gcount() == 0) break;

		/* If there's less than buffer_size bytes left of file. */
		if ((size_t)file.gcount() < buffer_size) {
			buffer_size = file.gcount();

			buf.resize(buffer_size);
			pad.resize(buffer_size);
			out_buf.resize(buffer_size);
		}

		for (size_t i = 0; i < buffer_size; i++) {
			pad[i] = (uint8_t)rng.next();
		}

		/* Loop is separated to promote SIMD. */
		for (size_t i = 0; i < buffer_size; i++) {
			out_buf[i] = buf[i] ^ pad[i];
		}

		outfile.write(out_buf.data(), buffer_size);
		pad_key_file.write(pad.data(), buffer_size);
	}

	file.close();
	outfile.close();
	pad_key_file.close();
}

void OneTimePad::decrypt(const std::string& file_path, const std::string& out_file_path, const std::string& pad_key_file_path) {
	std::basic_ifstream<uint8_t> file(file_path, std::ios::in | std::ios::binary);
	std::basic_ofstream<uint8_t> outfile(out_file_path, std::ios::out | std::ios::binary);
	std::basic_ifstream<uint8_t> in_pad_file(pad_key_file_path, std::ios::in | std::ios::binary);

	file.ignore(std::numeric_limits<std::streamsize>::max());
	std::streamsize file_size = file.gcount();
	file.clear();
	file.seekg(0, std::ios_base::beg);

	size_t buffer_size = std::min((size_t)file_size, OneTimePad::BUF_SIZE);

	OneTimePad::decrypt(file, outfile, in_pad_file, buffer_size);
}

void OneTimePad::decrypt(std::basic_ifstream<uint8_t>& file, std::basic_ofstream<uint8_t>& outfile, std::basic_ifstream<uint8_t>& pad_key_file,
	size_t buffer_size) {

	std::vector<uint8_t> pad(buffer_size);
	std::vector<uint8_t> out_buf(buffer_size);
	std::vector<uint8_t> buf(buffer_size);

	while (file.good() && pad_key_file.good()) {
		file.read(buf.data(), buffer_size);
		pad_key_file.read(pad.data(), buffer_size);

		if (file.gcount() == 0) break;

		/* If there's less than buffer_size bytes left of file. */
		if ((size_t)file.gcount() < buffer_size) {
			buffer_size = file.gcount();

			out_buf.resize(buffer_size);
			buf.resize(buffer_size);
			pad.resize(buffer_size);
		}

		for (size_t i = 0; i < buffer_size; i++) {
			out_buf[i] = buf[i] ^ pad[i];
		}

		outfile.write(out_buf.data(), buffer_size);
	}

	file.close();
	outfile.close();
	pad_key_file.close();

}