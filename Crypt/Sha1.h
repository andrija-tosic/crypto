#include <vector>
#include <array> 
#include <string>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cassert>
#include <future>
#include <iostream>

#define BIG_ENDIAN 0

#define SHA_DEBUG 0

using namespace std::chrono_literals;
/*
RFC 3174
https://www.rfc-editor.org/rfc/rfc3174
*/
class SHA1 {
	static constexpr size_t WORDS_PER_BLOCK = 16; // Word = 32-bit.
	static constexpr size_t BLOCK_BYTES = WORDS_PER_BLOCK * 4;

	static constexpr uint32_t H0 = 0x67452301;
	static constexpr uint32_t H1 = 0xEFCDAB89;
	static constexpr uint32_t H2 = 0x98BADCFE;
	static constexpr uint32_t H3 = 0x10325476;
	static constexpr uint32_t H4 = 0xC3D2E1F0;

	typedef uint32_t(*FunctionPointer)(uint32_t, uint32_t, uint32_t);

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
	static uint32_t ff(size_t t, uint32_t B, uint32_t C, uint32_t D) {
		if (t >= 0 && t <= 19) {
			return (B & C) | ((~B) & D);
		}
		else if (t >= 20 && t <= 39 || t >= 60 && t <= 79) {
			return B ^ C ^ D;
		}
		else { // if (t >= 40 && t <= 59) {
			return (B & C) | (B & D) | (C & D);
		}
	}

	static void final_pad_message(std::vector<uint8_t> message, size_t l, uint32_t& H0, uint32_t& H1, uint32_t& H2, uint32_t& H3, uint32_t& H4) {
		size_t space_for_length_append = 2 * sizeof(uint32_t);

#if SHA_DEBUG
		printf("[Message before padding]: \n");
		for (int i = 0; i < message.size(); i++) {
			printf("%02x", message[i]);
		}
		printf("\n");
#endif

		// a. "1" is appended.	
		message.push_back(0x80);

		/*
			Check to see if the current message block is too small to hold
			the initial padding bits and length.  If so, we will pad the
			block, process it, and then continue padding into a second
			block.
		*/
		if (message.size() > BLOCK_BYTES - space_for_length_append) {
			/* Edge case: size of block is between 56 and 64 bytes. One more block transform is needed. */
			/* Both blocks are padded to 64 bytes. */

			while (message.size() < BLOCK_BYTES) {
				message.push_back(0x00);
			}

#if SHA_DEBUG
			printf("\n[Before] H0 H1 H2 H3 H4: %x %x %x %x %x\n", H0, H1, H2, H3, H4);
#endif
			process_block(message, H0, H1, H2, H3, H4);
#if SHA_DEBUG
			printf("\n[After] H0 H1 H2 H3 H4: %x %x %x %x %x\n\n", H0, H1, H2, H3, H4);
#endif
			/* Processing final block. Vector is 64 bytes at this point. */
			message.resize(BLOCK_BYTES - space_for_length_append);
			std::fill(message.begin(), message.end(), 0x00);
		}
		else {
			/*
				b. "0"s are appended.  The number of "0"s will depend on the original
				length of the message.  The last 64 bits of the last 512-bit block
				are reserved for the length l of the original message.
			*/
			while (message.size() < BLOCK_BYTES - space_for_length_append) {
				message.push_back(0x00);
			}
		}

		/*
			c. Obtain the 2-word representation of l, the number of bits in the
			original message.  If l < 2^32 then the first word is all zeroes.
			Append these two words to the padded message.
		*/

		l = l * 8; // convert l from bytes to bits.

		uint32_t length_high = (uint32_t)(l >> 32);
		uint32_t length_low = (uint32_t)l;

#if BIG_ENDIAN
		upper_word_representation = make_big_endian_uint32(upper_word_representation);
		lower_word_representation = make_big_endian_uint32(lower_word_representation);
#endif
		message.push_back(length_high >> 24);
		message.push_back(length_high >> 16);
		message.push_back(length_high >> 8);
		message.push_back(length_high);

		message.push_back(length_low >> 24);
		message.push_back(length_low >> 16);
		message.push_back(length_low >> 8);
		message.push_back(length_low);


#if SHA_DEBUG
		printf("\n[Before] H0 H1 H2 H3 H4: %x %x %x %x %x\n", H0, H1, H2, H3, H4);
		process_block(message, H0, H1, H2, H3, H4);
		printf("\n[After] H0 H1 H2 H3 H4: %x %x %x %x %x\n\n", H0, H1, H2, H3, H4);
		printf("[Message after padding]: \n");
		for (int i = 0; i < message.size(); i++) {
			printf("%02x", message[i]);
		}
		printf("\n");
#endif
	}

	static uint32_t to_big_endian_uint32(uint32_t val) {
		val = ((val << 8) & 0xff00ff00) | ((val >> 8) & 0xff00ff);
		return (val << 16) | (val >> 16);
	}

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
	static uint32_t circular_left_shift(size_t n, uint32_t X) {
		return (X << n) | (X >> n);
	}

	static void process_block(const std::vector<uint8_t>& buffer_block,
		uint32_t& H0, uint32_t& H1, uint32_t& H2, uint32_t& H3, uint32_t& H4
	) {
		/* a. */
		std::array<uint32_t, 80> W{};

		size_t t;

		for (t = 0; t < 16; t++)
			W[t] = (buffer_block[t * 4] & 0xff) << 24
			| (buffer_block[t * 4 + 1] & 0xff) << 16
			| (buffer_block[t * 4 + 2] & 0xff) << 8
			| (buffer_block[t * 4 + 3] & 0xff) << 0;

		/* b. */
		for (; t < 80; t++)
			W[t] = SHA1::circular_left_shift(1, W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16]);

		/* c. */
		uint32_t A = H0, B = H1, C = H2, D = H3, E = H4;

		/* d. */
		for (size_t t = 0; t < 80; t++) {
			uint32_t TEMP = SHA1::circular_left_shift(5, A) + ff(t, B, C, D) + E + W[t] + K[t];

			E = D;  D = C;  C = SHA1::circular_left_shift(30, B);  B = A; A = TEMP;
		}

		/* e. */
		H0 += A, H1 += B, H2 += C, H3 += D, H4 += E;
	}

public:
	SHA1() = delete;
	~SHA1() = delete;
	SHA1(const SHA1&) = delete;
	SHA1(const SHA1&&) = delete;
	SHA1 operator=(const SHA1&) = delete;
	SHA1 operator=(const SHA1&&) = delete;

	static std::string hash(const std::string& file_path) {
		std::basic_ifstream<uint8_t> file(file_path, std::ios::in | std::ios::binary);

		if (file.bad()) {
			throw std::exception("File error");
		}

		//std::cout << "Thread ID: " << std::this_thread::get_id() << std::endl;

		file.ignore(std::numeric_limits<std::streamsize>::max());
		std::streamsize file_size = file.gcount();
		file.clear();
		file.seekg(0, std::ios_base::beg);

		size_t buffer_size = std::min((size_t)file_size, BLOCK_BYTES);

		std::vector<uint8_t> block_buf(BLOCK_BYTES);

		/* Digest. */

		uint32_t H0 = 0x67452301;
		uint32_t H1 = 0xEFCDAB89;
		uint32_t H2 = 0x98BADCFE;
		uint32_t H3 = 0x10325476;
		uint32_t H4 = 0xC3D2E1F0;

		//uint32_t H0 = 0x01234567;
		//uint32_t H1 = 0x89ABCDEF;
		//uint32_t H2 = 0xFEDCBA98;
		//uint32_t H3 = 0x76543210;
		//uint32_t H4 = 0xF0E1D2C3;

		size_t l = 0;

		std::streamsize c;

		while (file.good()) {
			/* Read a 512-bit block. */
			file.read(block_buf.data(), buffer_size);

			c = file.gcount();
			l += c;

			if (file.gcount() < BLOCK_BYTES) {
				/* Break and finalize by applying padding to the last block. */
				block_buf.resize(file.gcount());
				break;
			}

			std::cout << "SHA1 progress: " << ((double)l / file_size) * 100 << std::endl << std::flush;

			assert(block_buf.size() == BLOCK_BYTES && "process_block: invalid block size");
			SHA1::process_block(block_buf, H0, H1, H2, H3, H4);
		}

		assert(l == file_size && "Whole file wasn't read.");

		SHA1::final_pad_message(block_buf, l, H0, H1, H2, H3, H4);

		std::ostringstream result{};
		result << std::hex << std::setfill('0') << std::setw(8);

#if BIG_ENDIAN
		result << make_big_endian_uint32(H0)
			<< make_big_endian_uint32(H1)
			<< make_big_endian_uint32(H2)
			<< make_big_endian_uint32(H3)
			<< make_big_endian_uint32(H4);
#else
		result << H0 << H1 << H2 << H3 << H4;
#endif
		return result.str();
	};

	static bool compare_files(const std::string file1_path, const std::string file2_path) {
		if (file1_path == file2_path) {
			return true;
		}

		//std::future<std::string> hash1 = std::async(hash, file1_path);
		//std::future<std::string> hash2 = std::async(hash, file2_path);

		return SHA1::hash(file1_path) == SHA1::hash(file2_path);

		//return hash1.get() == hash2.get();
	}
};
