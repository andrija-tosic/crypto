#pragma once

#include <filesystem>
#include <string>
#include <fstream>

class OneTimePad
{
	static constexpr size_t BUF_SIZE = 1024;

public:
	static void Encrypt(const std::string& filePath, const std::string& outFilePath, const std::string& padKeyFilePath) {
		std::basic_ifstream<uint8_t> file(filePath, std::ios::in | std::ios::binary);
		std::basic_ofstream<uint8_t> outfile(outFilePath, std::ios::out | std::ios::binary);
		std::basic_ofstream<uint8_t> outPadFile(padKeyFilePath, std::ios::out | std::ios::binary);


		while (file.good()) {
			uint8_t pad[BUF_SIZE];
			uint8_t outBuf[BUF_SIZE];
			uint8_t buf[BUF_SIZE];

			file.read(buf, BUF_SIZE);

			for (size_t i = 0; i < BUF_SIZE; i++) {
				pad[i] = rand() % 256;
				outBuf[i] = buf[i] ^ pad[i];
			}

			outfile.write(outBuf, BUF_SIZE);
			outPadFile.write(pad, BUF_SIZE);
		}

		file.close();
		outfile.close();
		outPadFile.close();
	}

	static void Decrypt(const std::string& filePath, const std::string& outFilePath, const std::string& padKeyFilePath) {
		std::basic_ifstream<uint8_t> file(filePath, std::ios::in | std::ios::binary);
		std::basic_ofstream<uint8_t> outfile(outFilePath, std::ios::out | std::ios::binary);
		std::basic_ifstream<uint8_t> inPadFile(padKeyFilePath, std::ios::in | std::ios::binary);

		uint8_t outBuf[BUF_SIZE];

		while (file.good() && inPadFile.good()) {
			uint8_t pad[BUF_SIZE];
			uint8_t buf[BUF_SIZE];
			file.read(buf, BUF_SIZE);
			inPadFile.read(pad, BUF_SIZE);

			for (size_t i = 0; i < BUF_SIZE; i++) {
				outBuf[i] = buf[i] ^ pad[i];
			}

			outfile.write(outBuf, BUF_SIZE);
		}

		file.close();
		outfile.close();
		inPadFile.close();
	}
};
