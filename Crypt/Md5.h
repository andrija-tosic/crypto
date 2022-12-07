#pragma once
#include <string>
#include <fstream>
#include <vector>
#include <array>
#include <filesystem>

/*
RFC 1321
https://www.rfc-editor.org/rfc/rfc1321
*/
class MD5 {
	MD5() = delete;
	~MD5() = delete;
	MD5(const MD5&) = delete;
	MD5(const MD5&&) = delete;
	MD5 operator=(const MD5&) = delete;
	MD5 operator=(const MD5&&) = delete;

	/* Lookup table 4294967296 * sin(i). */
	static const uint32_t T[64];

	/*
		Round shift values
	*/
	static constexpr size_t s[64] = {
		7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
		5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
		4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
		6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
	};

	/*
		Constant K Values
	*/
	static constexpr uint32_t K[64] = {
		0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
		0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
		0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
		0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
		0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
		0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
		0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
		0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
		0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
		0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
		0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
		0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
		0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
		0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
		0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
		0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
	};

	static uint32_t F(uint32_t x, uint32_t y, uint32_t z) {
		return x & y | ~x & z;
	}

	static uint32_t G(uint32_t x, uint32_t y, uint32_t z) {
		return x & z | y & ~z;
	}

	static uint32_t H(uint32_t x, uint32_t y, uint32_t z) {
		return x ^ y ^ z;
	}

	static uint32_t I(uint32_t x, uint32_t y, uint32_t z) {
		return y ^ (x | ~z);
	}

	static uint32_t rotate_left(uint32_t x, int n) {
		return (x << n) | (x >> (32 - n));
	}

	static void process_16word_blocks(std::vector<uint16_t> M) {

		size_t N = M.size();

		std::vector<uint16_t> X;

		/* Process each 16-word block. Word = 32-bit. */
		for (size_t i = 0; i < N / 16; i++) {

			/* Copy block i into X. */
			for (size_t j = 0; j < 16; j++) {
				X[i] = M[i * 16 + j];
			}

			uint32_t A = 0x01234567;
			uint32_t B = 0x89abcdef;
			uint32_t C = 0xfedcba98;
			uint32_t D = 0x76543210;

			/* Save A as AA, B as BB, C as CC, and D as DD. */
			uint32_t AA = A;
			uint32_t BB = B;
			uint32_t CC = C;
			uint32_t DD = D;

			uint32_t f, g;

			for (uint32_t k = 0; k < 64; ++k)
			{
				/* 
					MD5 basic transformation. Transforms state based on block.
				 */
				if (k <= 15)
				{
					/* Round 1. */
					/*
						Let [abcd k s i] denote the operation
						a = b + ((a + F(b,c,d) + X[k] + T[i]) <<< s).
					*/

					/* Do the following 16 operations. */
					/*
						[ABCD  0  7  1][DABC  1 12  2][CDAB  2 17  3][BCDA  3 22  4]
						[ABCD  4  7  5][DABC  5 12  6][CDAB  6 17  7][BCDA  7 22  8]
						[ABCD  8  7  9][DABC  9 12 10][CDAB 10 17 11][BCDA 11 22 12]
						[ABCD 12  7 13][DABC 13 12 14][CDAB 14 17 15][BCDA 15 22 16]
					*/
					f = F(B, C, D);
					g = k;
				}
				else if (k >= 16 && k <= 31)
				{
					/* Round 2. */
					/*
						Let [abcd k s i] denote the operation
						a = b + ((a + G(b,c,d) + X[k] + T[i]) <<< s).
					*/

					/* Do the following 16 operations. */
					/*
						[ABCD  1  5 17][DABC  6  9 18][CDAB 11 14 19][BCDA  0 20 20]
						[ABCD  5  5 21][DABC 10  9 22][CDAB 15 14 23][BCDA  4 20 24]
						[ABCD  9  5 25][DABC 14  9 26][CDAB  3 14 27][BCDA  8 20 28]
						[ABCD 13  5 29][DABC  2  9 30][CDAB  7 14 31][BCDA 12 20 32]
					*/
					f = G(B, C, D);
					g = ((5 * k) + 1) % 16;
				}
				else if (k >= 32 && k <= 47)
				{
					/* Round 3. */
					/*
						Let [abcd k s t] denote the operation
						  a = b + ((a + H(b,c,d) + X[k] + T[i]) <<< s
					*/

					/* Do the following 16 operations. */
					/*
						[ABCD  5  4 33][DABC  8 11 34][CDAB 11 16 35][BCDA 14 23 36]
						[ABCD  1  4 37][DABC  4 11 38][CDAB  7 16 39][BCDA 10 23 40]
						[ABCD 13  4 41][DABC  0 11 42][CDAB  3 16 43][BCDA  6 23 44]
						[ABCD  9  4 45][DABC 12 11 46][CDAB 15 16 47][BCDA  2 23 48]
					*/
					f = H(B, C, D);
					g = ((3 * k) + 5) % 16;
				}
				else if (k >= 48)
				{
					/* Round 4. */
					/*
						Let [abcd k s t] denote the operation
						a = b + ((a + I(b,c,d) + X[k] + T[i]) <<< s).
					*/

					/* Do the following 16 operations. */
					/*
						[ABCD  0  6 49][DABC  7 10 50][CDAB 14 15 51][BCDA  5 21 52]
						[ABCD 12  6 53][DABC  3 10 54][CDAB 10 15 55][BCDA  1 21 56]
						[ABCD  8  6 57][DABC 15 10 58][CDAB  6 15 59][BCDA 13 21 60]
						[ABCD  4  6 61][DABC 11 10 62][CDAB  2 15 63][BCDA  9 21 64]
					*/
					f = I(C, B, D);
					g = (7 * k) % 16;
				}

				uint32_t dtemp = DD;
				DD = CC;
				CC = BB;
				BB = BB + left_rotate((AA + f + K[k] + M[g]), s[k]);
				AA = dtemp;
			}

			A += AA;
			B += BB;
			C += CC;
			D += DD;
		}
	}

	static uint32_t left_rotate(uint32_t x, size_t c) {
		return (x << c) | (x >> (32 - c));
	}

public:
	static std::array<uint8_t, 128> hash_file(const std::string& file_path) {
		std::basic_ifstream<uint8_t> file(file_path, std::ios::in | std::ios::binary);

		uintmax_t file_size = std::filesystem::file_size(file_path);

		size_t multiple = 512;

		while (multiple <= file_size) {
			multiple += 512;
		}

		size_t padding = multiple - file_size;
	}

	static bool compare(const std::string& file1_path, const std::string& file2_path) {

	}

};
