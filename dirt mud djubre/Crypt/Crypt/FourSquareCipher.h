#pragma once
#include <array>
#include <filesystem>
#include <fstream>
#include <vector>


class FourSquareCipher
{
private:
	static std::vector<std::pair<char, char>> TextToBigrams(std::string text) {
		std::vector<std::pair<char, char>> bigrams{};

		std::erase_if(text, isspace);

		for (size_t i = 0; i < text.length(); i += 2) {
			std::pair<char, char> chars{};
			chars.first = text[i];

			if (i + 1 < text.length()) {
				chars.second = text[i + 1];
			}
			else {
				chars.second = ' ';
			}

			bigrams.push_back(chars);

			int a = 5;
		}

		return bigrams;
	}

	static std::vector<std::pair<char, char>> EncryptBigram(std::vector<std::pair<char, char>> bigram,
	                                                        const std::string_view& keyBlock1,
	                                                        const std::string_view& keyBlock2) {

		int i = 0;

		const std::string alphabetBlock = "abcdefghiklmnopqrstuvwxyz";

		for (auto& [fst, snd] : bigram) {
			const size_t loc1 = alphabetBlock.find(fst);
			const size_t loc2 = alphabetBlock.find(snd);

			if (loc1 == std::string::npos) {
				bigram[i].first = fst;
			}
			else {
				bigram[i].first = keyBlock1[5 * (loc1 / 5) + loc2 % 5];
			}

			if (loc2 == std::string::npos) {
				bigram[i].second = snd;
			}
			else {
				bigram[i].second = keyBlock2[loc1 % 5 + 5 * (loc2 / 5)];
			}

			i++;
		}

		return bigram;
	}

	static std::vector<std::pair<char, char>> DecryptBigram(std::vector<std::pair<char, char>> bigram,
	                                                        const std::string_view& keyBlock1,
	                                                        const std::string_view& keyBlock2) {
		int i = 0;

		const std::string alphabetBlock = "abcdefghiklmnopqrstuvwxyz";

		for (auto& [fst, snd] : bigram) {
			const size_t loc1 = keyBlock1.find(fst);
			const size_t loc2 = keyBlock2.find(snd);

			if (loc1 == std::string::npos) {
				bigram[i].first = fst;
			}
			else {
				bigram[i].first = alphabetBlock[5 * (loc1 / 5) + loc2 % 5];
			}

			if (loc2 == std::string::npos) {
				bigram[i].second = snd;
			}
			else {
				bigram[i].second = alphabetBlock[loc1 % 5 + 5 * (loc2 / 5)];
			}

			i++;
		}

		return bigram;
	}

public:
	static void Encrypt(const std::string& filePath, const std::string& outFilePath) {
		std::basic_ifstream<char> file(filePath, std::ios::in);
		std::basic_ofstream<char> outfile(outFilePath, std::ios::out);

		file.ignore(std::numeric_limits<std::streamsize>::max());
		std::streamsize length = file.gcount();
		file.clear();
		file.seekg(0, std::ios_base::beg);

		std::streamsize bufSize = std::min(static_cast<std::streamsize>(1024), length);
		char* textBuf = new char[bufSize];

		while (file.good()) {
			file.read(textBuf, bufSize);

			const std::string t(textBuf, textBuf + bufSize);

			std::vector<std::pair<char, char>> bigram = TextToBigrams(t);
			std::vector<std::pair<char, char>> encryptedBigram = EncryptBigram(
				bigram, "zgptfoihmuwdrcnykeqaxvsbl", "mfnbdcrhsaxyogvituewlqzkp");

			std::string outStr{};
			for (auto& [fst, snd] : encryptedBigram) {
				outStr += fst;
				outStr += snd;
			}

			outfile.write(outStr.c_str(), outStr.size());
		}

		delete[] textBuf;

		file.close();
		outfile.close();
	}

	static void Decrypt(const std::string& filePath, const std::string& outFilePath) {
		std::basic_ifstream<char> file(filePath, std::ios::in);
		std::basic_ofstream<char> outfile(outFilePath, std::ios::out);

		file.ignore(std::numeric_limits<std::streamsize>::max());
		std::streamsize length = file.gcount();
		file.clear();
		file.seekg(0, std::ios_base::beg);

		std::streamsize bufSize = std::min(static_cast<std::streamsize>(1024), length);
		char* textBuf = new char[bufSize];

		while (file.good()) {
			file.read(textBuf, bufSize);

			const std::string t(textBuf, textBuf + bufSize);

			std::vector<std::pair<char, char>> bigram = TextToBigrams(t);
			std::vector<std::pair<char, char>> decryptedBigram = DecryptBigram(bigram, "zgptfoihmuwdrcnykeqaxvsbl",
			                                                                   "mfnbdcrhsaxyogvituewlqzkp");

			std::string outStr{};
			for (auto& [fst, snd] : decryptedBigram) {
				outStr += fst;
				outStr += snd;
			}

			outfile.write(outStr.c_str(), outStr.size());
		}

		delete[] textBuf;
		file.close();
		outfile.close();

	}
};
