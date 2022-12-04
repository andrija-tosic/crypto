#pragma once
#include <cstdint>

#define MX ((z>>5^y<<2) + (y>>3^z<<4)^(sum^y) + (k[p&3^e]^z))

class Xxtea
{
	static constexpr unsigned long DELTA = 0x9e3779b9;

	static void encrypt(long* v, const long n, const long* k) {
		unsigned long z = v[n - 1], y = v[0], sum = 0;
		long p;
		const long rounds = 6 + 52 / n;
		for (long i = 0; i < rounds; i++) {
			sum += DELTA;
			const unsigned long e = sum >> 2 & 3;
			for (p = 0; p < n - 1; p++) {
				y = v[p + 1];
				z = v[p] += MX;
			}
			y = v[0];
			z = v[n - 1] += MX;
		}
	}

	static void decrypt(long* v, long n, const long* k) {
		unsigned long z = v[n - 1], y = v[0];
		long m, p;
		const long rounds = 6 + 52 / n;

		n = -n;
		for (unsigned long sum = rounds * DELTA; sum != 0; sum -= DELTA) {
			const unsigned long e = (sum >> 2) & 3;
			for (p = n - 1; p > 0; p--) {
				z = v[p - 1];
				y = v[p] -= MX;
			}
			z = v[n - 1];
			y = v[0] -= MX;
		}
	}
};
