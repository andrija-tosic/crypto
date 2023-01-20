#include "FourSquareCipher.h"

std::vector<std::pair<char, char>> FourSquareCipher::text_to_bigrams(std::string text) {
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
	}

	return bigrams;
}

std::vector<std::pair<char, char>> FourSquareCipher::encrypt_bigram(std::vector<std::pair<char, char>> bigram, const std::string_view& key_block1, const std::string_view& key_block2) {

	int i = 0;

	const std::string alphabet_block = "abcdefghiklmnopqrstuvwxyz";

	for (auto& [fst, snd] : bigram) {
		const size_t loc1 = alphabet_block.find(fst);
		const size_t loc2 = alphabet_block.find(snd);

		if (loc1 == std::string::npos) {
			bigram[i].first = fst;
		}
		else {
			bigram[i].first = key_block1[5 * (loc1 / 5) + loc2 % 5];
		}

		if (loc2 == std::string::npos) {
			bigram[i].second = snd;
		}
		else {
			bigram[i].second = key_block2[loc1 % 5 + 5 * (loc2 / 5)];
		}

		i++;
	}

	return bigram;
}

std::vector<std::pair<char, char>> FourSquareCipher::decrypt_bigram(std::vector<std::pair<char, char>> bigram, const std::string_view& key_block1, const std::string_view& key_block2) {
	int i = 0;

	const std::string alphabet_block = "abcdefghiklmnopqrstuvwxyz";

	for (auto& [fst, snd] : bigram) {
		const size_t loc1 = key_block1.find(fst);
		const size_t loc2 = key_block2.find(snd);

		if (loc1 == std::string::npos) {
			bigram[i].first = fst;
		}
		else {
			bigram[i].first = alphabet_block[5 * (loc1 / 5) + loc2 % 5];
		}

		if (loc2 == std::string::npos) {
			bigram[i].second = snd;
		}
		else {
			bigram[i].second = alphabet_block[loc1 % 5 + 5 * (loc2 / 5)];
		}

		i++;
	}

	return bigram;
}

void FourSquareCipher::encrypt(const std::string& file_path, const std::string& out_file_path, const std::string& key1, const std::string& key2) {
	std::basic_ifstream<char> file(file_path, std::ios::in);
	std::basic_ofstream<char> outfile(out_file_path, std::ios::out);

	uintmax_t file_size = std::filesystem::file_size(file_path);

	uintmax_t buf_size = std::min((uintmax_t)1024, file_size);
	auto text_buf = new char[buf_size];

	while (file.good()) {
		file.read(text_buf, buf_size);

		const std::string t(text_buf, text_buf + buf_size);

		std::vector<std::pair<char, char>> bigram = text_to_bigrams(t);
		std::vector<std::pair<char, char>> encrypted_bigram = encrypt_bigram(
			bigram, key1, key2);

		std::string out_str{};
		for (auto& [fst, snd] : encrypted_bigram) {
			out_str += fst;
			out_str += snd;
		}

		outfile.write(out_str.c_str(), out_str.size());
	}

	delete[] text_buf;

	file.close();
	outfile.close();
}

void FourSquareCipher::decrypt(const std::string& file_path, const std::string& out_file_path, const std::string& key1, const std::string& key2) {
	std::basic_ifstream<char> file(file_path, std::ios::in);
	std::basic_ofstream<char> outfile(out_file_path, std::ios::out);

	uintmax_t file_size = std::filesystem::file_size(file_path);

	uintmax_t buf_size = std::min((uintmax_t)1024, file_size);
	auto text_buf = new char[buf_size];

	while (file.good()) {
		file.read(text_buf, buf_size);

		const std::string t(text_buf, text_buf + buf_size);

		std::vector<std::pair<char, char>> bigram = text_to_bigrams(t);
		std::vector<std::pair<char, char>> decrypted_bigram = decrypt_bigram(bigram, key1, key2);

		std::string out_str{};
		for (auto& [fst, snd] : decrypted_bigram) {
			out_str += fst;
			out_str += snd;
		}

		outfile.write(out_str.c_str(), out_str.size());
	}

	delete[] text_buf;
	file.close();
	outfile.close();

}
