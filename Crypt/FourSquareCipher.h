#pragma once
#include <array>
#include <filesystem>
#include <fstream>
#include <vector>


class FourSquareCipher
{
private:
	static std::vector<std::pair<char, char>> text_to_bigrams(std::string text);

	static std::vector<std::pair<char, char>> encrypt_bigram(std::vector<std::pair<char, char>> bigram,
		const std::string_view& key_block1,
		const std::string_view& key_block2);

	static std::vector<std::pair<char, char>> decrypt_bigram(std::vector<std::pair<char, char>> bigram,
		const std::string_view& key_block1,
		const std::string_view& key_block2);

public:
	FourSquareCipher() = delete;
	~FourSquareCipher() = delete;
	FourSquareCipher(const FourSquareCipher&) = delete;
	FourSquareCipher(const FourSquareCipher&&) = delete;
	FourSquareCipher operator=(const FourSquareCipher&) = delete;
	FourSquareCipher operator=(const FourSquareCipher&&) = delete;


	static void encrypt(const std::string& file_path, const std::string& out_file_path, const std::string& key1, const std::string& key2);

	static void decrypt(const std::string& file_path, const std::string& out_file_path, const std::string& key1, const std::string& key2);
};
