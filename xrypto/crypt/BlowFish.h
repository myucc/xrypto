#pragma once

class BlowFish
{
public:
	BlowFish(const char* key, unsigned long long length);
	BlowFish(BlowFish const&) = delete;
	void decrypt(unsigned int& xl, unsigned int& xr);
	void encrypt(unsigned int& xl, unsigned int& xr);
private:
	unsigned int F(unsigned int x);
	unsigned int Z[18];
	unsigned int X[4][256];
};