#pragma once
#include <cstdint>
#include <stdlib.h>
#include <random>

class RNG {
	struct xorshift128_state {
		uint32_t x[4];
	} state;

	uint32_t xorshift128();

	struct splitmix64_state {
		uint64_t s;
	} splitmix64_state;

	uint64_t splitmix64();


	void xorshift128_init(uint64_t seed);

public:
	RNG();

	RNG(const RNG&) = delete;
	RNG(const RNG&&) = delete;
	RNG operator=(const RNG&) = delete;
	RNG operator=(const RNG&&) = delete;

	uint64_t next();

};