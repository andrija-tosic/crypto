#pragma once

#include <filesystem>
#include <string>
#include <fstream>

namespace OneTimePad
{
	void Encrypt(const std::string& filePath, const std::string& outFilePath, const std::string& padKeyFilePath) {
		std::basic_ifstream<uint8_t> file(filePath, std::ios::in | std::ios::binary);
		std::basic_ofstream<uint8_t> outfile(outFilePath, std::ios::out | std::ios::binary);
		std::basic_ofstream<uint8_t> outPadFile(padKeyFilePath, std::ios::out | std::ios::binary);

		constexpr size_t BUF_SIZE = 1024;

		uint8_t outBuf[BUF_SIZE];
		uint8_t pad[BUF_SIZE];

		while (file.good()) {
			uint8_t buf[BUF_SIZE];
			file.read(buf, BUF_SIZE);

			for (int i = 0; i < BUF_SIZE; i++) {
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

	void Decrypt(const std::string& filePath, const std::string& outFilePath, const std::string& padKeyFilePath) {
		std::basic_ifstream<uint8_t> file(filePath, std::ios::in | std::ios::binary);
		std::basic_ofstream<uint8_t> outfile(outFilePath, std::ios::out | std::ios::binary);
		std::basic_ifstream<uint8_t> inPadfile(padKeyFilePath, std::ios::in | std::ios::binary);

		constexpr size_t BUF_SIZE = 1024;

		uint8_t outBuf[BUF_SIZE];
		uint8_t pad[BUF_SIZE];

		while (file.good() && inPadfile.good()) {
			uint8_t buf[BUF_SIZE];
			file.read(buf, BUF_SIZE);
			inPadfile.read(pad, BUF_SIZE);

			for (int i = 0; i < BUF_SIZE; i++) {
				outBuf[i] = buf[i] ^ pad[i];
			}

			outfile.write(outBuf, BUF_SIZE);
		}

		file.close();
		outfile.close();
		inPadfile.close();
	}
};

