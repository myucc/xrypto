#include <sstream>
#include <iomanip>
#include <vector>
#include <random>
#include <windows.h>
#include <fstream>
#include <filesystem>

#include "BlowFish.h"
#include "aes128_xxx.h"
#include "sha256.h"
#include "sha512.h"

namespace fs = std::filesystem;

BOOL exists(const std::wstring& path);
std::string w2c(const std::wstring& wstr);
std::wstring c2w(const std::string& str);
std::string to_hex(const std::string& input);
std::string from_uint(uint32_t sh);
std::string base64_encrypt(const std::string& msg);
std::string base64_decrypt(const std::string& enc_msg);
std::string bFish_decrypt(const std::string& _msg_enc, const std::string& _key);
std::string bFish_encrypt(const std::string& msg, const std::string& _key);
std::string sha256_hash_str(const std::string& input);
std::string sha512_hash_str(const std::string& input);
std::string sha256_hash_file(const std::wstring& path);
std::string sha512_hash_file(const std::wstring& path);
void decrypt_stream(FILE* infp, const std::wstring& file_path, wchar_t* passwd, int passlen);
void encrypt_stream(FILE* infp, FILE* outfp, wchar_t* passwd, int passlen);

template <class T>
T rstring(std::size_t length)
{
	T chs = L"abcdefghijklmnopqrstuvwxyz0123456789", st;
	std::random_device rd;
	std::mt19937 g(rd());
	std::uniform_int_distribution<> d(0, chs.size() - 1);

	for (std::size_t i = 0; i < length; ++i) st += chs[d(g)];
	return st;
}