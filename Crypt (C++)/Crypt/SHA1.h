#include <vector>
#include <array> 
#include <string>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cassert>
#include <future>
#include <iostream>

#define SHA_DEBUG 0

using namespace std::chrono_literals;
/*
RFC 3174
https://www.rfc-editor.org/rfc/rfc3174
*/
class SHA1 {
	static constexpr size_t WORDS_PER_BLOCK = 16; // Word = 32-bit.
	static constexpr size_t BLOCK_BYTES = WORDS_PER_BLOCK * 4;

	/*
		A sequence of constant words K(0), K(1), ... , K(79) is used in the
		SHA-1.  In hex these are given by
	*/
	static constexpr uint32_t K[80] = {
		0x5A827999,0x5A827999,0x5A827999,0x5A827999,0x5A827999,0x5A827999,0x5A827999,0x5A827999,0x5A827999,0x5A827999,
		0x5A827999,0x5A827999,0x5A827999,0x5A827999,0x5A827999,0x5A827999,0x5A827999,0x5A827999,0x5A827999,0x5A827999,

		0x6ED9EBA1,0x6ED9EBA1,0x6ED9EBA1,0x6ED9EBA1,0x6ED9EBA1,0x6ED9EBA1,0x6ED9EBA1,0x6ED9EBA1,0x6ED9EBA1,0x6ED9EBA1,
		0x6ED9EBA1,0x6ED9EBA1,0x6ED9EBA1,0x6ED9EBA1,0x6ED9EBA1,0x6ED9EBA1,0x6ED9EBA1,0x6ED9EBA1,0x6ED9EBA1,0x6ED9EBA1,

		0x8F1BBCDC,0x8F1BBCDC,0x8F1BBCDC,0x8F1BBCDC,0x8F1BBCDC,0x8F1BBCDC,0x8F1BBCDC,0x8F1BBCDC,0x8F1BBCDC,0x8F1BBCDC,
		0x8F1BBCDC,0x8F1BBCDC,0x8F1BBCDC,0x8F1BBCDC,0x8F1BBCDC,0x8F1BBCDC,0x8F1BBCDC,0x8F1BBCDC,0x8F1BBCDC,0x8F1BBCDC,

		0xCA62C1D6,0xCA62C1D6,0xCA62C1D6,0xCA62C1D6,0xCA62C1D6,0xCA62C1D6,0xCA62C1D6,0xCA62C1D6,0xCA62C1D6,0xCA62C1D6,
		0xCA62C1D6,0xCA62C1D6,0xCA62C1D6,0xCA62C1D6,0xCA62C1D6,0xCA62C1D6,0xCA62C1D6,0xCA62C1D6,0xCA62C1D6,0xCA62C1D6
	};

	/*
		 A sequence of logical functions f(0), f(1),..., f(79) is used in
		 SHA-1.  Each f(t), 0 <= t <= 79, operates on three 32-bit words B, C,
		 D and produces a 32-bit word as output.  f(t;B,C,D) is defined as
		 follows: for words B, C, D,
	*/
	static uint32_t ff(size_t t, uint32_t B, uint32_t C, uint32_t D);

	static void final_pad_message(std::vector<uint8_t> message, size_t l, uint32_t& H0, uint32_t& H1, uint32_t& H2, uint32_t& H3, uint32_t& H4);

	/*
		c. The circular left shift operation S^n(X), where X is a word and n
		is an integer with 0 <= n < 32, is defined by

		 S^n(X)  =  (X << n) OR (X >> 32-n).

		 In the above, X << n is obtained as follows: discard the left-most
		 n bits of X and then pad the result with n zeroes on the right
		 (the result will still be 32 bits).  X >> n is obtained by
		 discarding the right-most n bits of X and then padding the result
		 with n zeroes on the left.  Thus S^n(X) is equivalent to a
		 circular shift of X by n positions to the left.
	*/
	static uint32_t circular_left_shift(size_t n, uint32_t X);

	static void process_block(const std::vector<uint8_t>& buffer_block,
		uint32_t& H0, uint32_t& H1, uint32_t& H2, uint32_t& H3, uint32_t& H4
	);

public:
	SHA1() = delete;
	~SHA1() = delete;
	SHA1(const SHA1&) = delete;
	SHA1(const SHA1&&) = delete;
	SHA1 operator=(const SHA1&) = delete;
	SHA1 operator=(const SHA1&&) = delete;

	static std::string hash(const std::string& file_path);;

	static bool compare_files(const std::string& file1_path, const std::string& file2_path);
};
