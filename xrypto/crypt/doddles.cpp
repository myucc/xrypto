#include "doddles.h"
#include <codecvt>

void encrypt_stream(FILE* infp, FILE* outfp, wchar_t* passwd, int passlen)
{
	aes_context                 aes_ctx;
	sha256_context              sha_ctx;
	aescrypt_hdr                aeshdr;
	sha256_t                    digest;
	unsigned char               IV[16];
	unsigned char               iv_key[48];
	int                         i, j, n;
	unsigned char               buffer[32];
	unsigned char               ipad[64], opad[64];
	unsigned char               tag_buffer[256];
	HCRYPTPROV                  hProv;
	DWORD                       result_code;

	if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) return;

	memset(iv_key, 0, 48);
	for (i = 0; i < 48; i += 16)
	{
		memset(buffer, 0, 32);
		sha256_starts(&sha_ctx);
		for (j = 0; j < 256; j++)
		{
			if (!CryptGenRandom(hProv, 32, (BYTE*)buffer)) { return; }
			sha256_update(&sha_ctx, buffer, 32);
		}
		sha256_finish(&sha_ctx, digest);
		memcpy(iv_key + i, digest, 16);
	}

	buffer[0] = 'S';
	buffer[1] = 'E';
	buffer[2] = 'X';
	buffer[3] = (unsigned char)0x02;
	buffer[4] = '\0';
	if (fwrite(buffer, 1, 5, outfp) != 5)
	{
		CryptReleaseContext(hProv, 0);
		return;
	}

	j = 11 + (int)strlen(PROG_NAME) + 1 + (int)strlen(PROG_VERSION);

	if (j < 256)
	{
		buffer[0] = '\0';
		buffer[1] = (unsigned char)(j & 0xff);
		if (fwrite(buffer, 1, 2, outfp) != 2)
		{
			CryptReleaseContext(hProv, 0);
			return;
		}

		strncpy_s((char*)tag_buffer, sizeof(tag_buffer), "809VYF213F", 255);
		tag_buffer[255] = '\0';
		if (fwrite(tag_buffer, 1, 11, outfp) != 11)
		{
			CryptReleaseContext(hProv, 0);
			return;
		}

		sprintf_s((char*)tag_buffer, sizeof(tag_buffer), "%s %s", PROG_NAME, PROG_VERSION);
		j = (int)strlen((char*)tag_buffer);
		if (fwrite(tag_buffer, 1, j, outfp) != j)
		{
			CryptReleaseContext(hProv, 0);
			return;
		}
	}

	buffer[0] = '\0';
	buffer[1] = (unsigned char)128;
	if (fwrite(buffer, 1, 2, outfp) != 2)
	{
		CryptReleaseContext(hProv, 0);
		return;
	}
	memset(tag_buffer, 0, 128);
	if (fwrite(tag_buffer, 1, 128, outfp) != 128)
	{
		CryptReleaseContext(hProv, 0);
		return;
	}

	buffer[0] = '\0';
	buffer[1] = '\0';
	if (fwrite(buffer, 1, 2, outfp) != 2)
	{
		CryptReleaseContext(hProv, 0);
		return;
	}

	sha256_starts(&sha_ctx);

	for (i = 0; i < 256; i++)
	{
		if (!CryptGenRandom(hProv,32,(BYTE*)buffer))
		{
			CryptReleaseContext(hProv, 0);
			return;
		}
		sha256_update(&sha_ctx,buffer,32);
	}

	sha256_finish(&sha_ctx, digest);
	memcpy(IV, digest, 16);
	CryptReleaseContext(hProv, 0);

	if (fwrite(IV, 1, 16, outfp) != 16) { return; }

	memset(digest, 0, 32);
	memcpy(digest, IV, 16);
	for (i = 0; i < 8192; i++)
	{
		sha256_starts(&sha_ctx);
		sha256_update(&sha_ctx, digest, 32);
		sha256_update(&sha_ctx,
			(unsigned char*)passwd,
			(unsigned long)(passlen * sizeof(wchar_t)));
		sha256_finish(&sha_ctx, digest);
	}

	aes_set_key(&aes_ctx, digest, 256);
	memset(ipad, 0x36, 64);
	memset(opad, 0x5C, 64);

	for (i = 0; i < 32; i++)
	{
		ipad[i] ^= digest[i];
		opad[i] ^= digest[i];
	}

	sha256_starts(&sha_ctx);
	sha256_update(&sha_ctx, ipad, 64);

	for (i = 0; i < 48; i += 16)
	{
		memcpy(buffer, iv_key + i, 16);
		for (j = 0; j < 16; j++) { buffer[j] ^= IV[j]; }

		aes_encrypt(&aes_ctx, buffer, buffer);
		sha256_update(&sha_ctx, buffer, 16);

		if (fwrite(buffer, 1, 16, outfp) != 16) { return; }

		memcpy(IV, buffer, 16);
	}

	sha256_finish(&sha_ctx, digest);
	sha256_starts(&sha_ctx);
	sha256_update(&sha_ctx, opad, 64);
	sha256_update(&sha_ctx, digest, 32);
	sha256_finish(&sha_ctx, digest);
	if (fwrite(digest, 1, 32, outfp) != 32) { return; }

	memcpy(IV, iv_key, 16);
	aes_set_key(&aes_ctx, iv_key + 16, 256);
	memset(ipad, 0x36, 64);
	memset(opad, 0x5C, 64);

	for (i = 0; i < 32; i++)
	{
		ipad[i] ^= iv_key[i + 16];
		opad[i] ^= iv_key[i + 16];
	}

	memset(iv_key, 0, 48);

	sha256_starts(&sha_ctx);
	sha256_update(&sha_ctx, ipad, 64);

	aeshdr.last_block_size = 0;

	while ((n = (int)fread(buffer, 1, 16, infp)) > 0)
	{
		for (i = 0; i < 16; i++) { buffer[i] ^= IV[i]; }

		aes_encrypt(&aes_ctx, buffer, buffer);
		sha256_update(&sha_ctx, buffer, 16);

		if (fwrite(buffer, 1, 16, outfp) != 16) { return; }

		memcpy(IV, buffer, 16);
		aeshdr.last_block_size = n;
	}

	if (n < 0) { return; }

	buffer[0] = (char)(aeshdr.last_block_size & 0x0F);
	if (fwrite(buffer, 1, 1, outfp) != 1) { return; }

	sha256_finish(&sha_ctx, digest);
	sha256_starts(&sha_ctx);
	sha256_update(&sha_ctx, opad, 64);
	sha256_update(&sha_ctx, digest, 32);
	sha256_finish(&sha_ctx, digest);
	if (fwrite(digest, 1, 32, outfp) != 32) { return; }
	if (fflush(outfp)) { return; }
}

void decrypt_stream(FILE* infp, const std::wstring& file_path, wchar_t* passwd, int passlen)
{
	aes_context                 aes_ctx;
	sha256_context              sha_ctx;
	aescrypt_hdr                aeshdr;
	sha256_t                    digest;
	unsigned char               IV[16];
	unsigned char               iv_key[48];
	int                         i, j, n, bytes_read;
	unsigned char               buffer[64], buffer2[32];
	unsigned char* head, * tail;
	unsigned char               ipad[64], opad[64];
	int                         reached_eof = 0;

	if ((bytes_read = (int)fread(&aeshdr, 1, sizeof(aeshdr), infp)) != sizeof(aescrypt_hdr)) { return; }
	if (!(aeshdr.aes[0] == 'S' && aeshdr.aes[1] == 'E' && aeshdr.aes[2] == 'X')) { return; }

	if (aeshdr.version == 0) { aeshdr.last_block_size = (aeshdr.last_block_size & 0x0F); }
	else if (aeshdr.version > 0x02) { return; }

	if (aeshdr.version >= 0x02)
	{
		do
		{
			if ((bytes_read = (int)fread(buffer, 1, 2, infp)) != 2) { return; }
			i = j = (((int)buffer[0]) << 8) | (int)buffer[1];
			while (i--)
			{
				if ((bytes_read = (int)fread(buffer, 1, 1, infp)) != 1) { return; }
			}
		} while (j);
	}

	if ((bytes_read = (int)fread(IV, 1, 16, infp)) != 16) { return; }

	memset(digest, 0, 32);
	memcpy(digest, IV, 16);
	for (i = 0; i < 8192; i++)
	{
		sha256_starts(&sha_ctx);
		sha256_update(&sha_ctx, digest, 32);
		sha256_update(&sha_ctx,
			(unsigned char*)passwd,
			(unsigned long)(passlen * sizeof(wchar_t)));
		sha256_finish(&sha_ctx, digest);
	}

	aes_set_key(&aes_ctx, digest, 256);
	memset(ipad, 0x36, 64);
	memset(opad, 0x5C, 64);

	for (i = 0; i < 32; i++)
	{
		ipad[i] ^= digest[i];
		opad[i] ^= digest[i];
	}

	sha256_starts(&sha_ctx);
	sha256_update(&sha_ctx, ipad, 64);

	if (aeshdr.version >= 0x01)
	{
		for (i = 0; i < 48; i += 16)
		{
			if ((bytes_read = (int)fread(buffer, 1, 16, infp)) != 16) { return; }

			memcpy(buffer2, buffer, 16);
			sha256_update(&sha_ctx, buffer, 16);
			aes_decrypt(&aes_ctx, buffer, buffer);

			for (j = 0; j < 16; j++)
			{
				iv_key[i + j] = (buffer[j] ^ IV[j]);
			}

			memcpy(IV, buffer2, 16);
		}

		sha256_finish(&sha_ctx, digest);
		sha256_starts(&sha_ctx);
		sha256_update(&sha_ctx, opad, 64);
		sha256_update(&sha_ctx, digest, 32);
		sha256_finish(&sha_ctx, digest);

		if ((bytes_read = (int)fread(buffer, 1, 32, infp)) != 32) { return; }

		if (memcmp(digest, buffer, 32)) { return; }
		memcpy(IV, iv_key, 16);
		aes_set_key(&aes_ctx, iv_key + 16, 256);
		memset(ipad, 0x36, 64);
		memset(opad, 0x5C, 64);

		for (i = 0; i < 32; i++)
		{
			ipad[i] ^= iv_key[i + 16];
			opad[i] ^= iv_key[i + 16];
		}

		memset(iv_key, 0, 48);
		sha256_starts(&sha_ctx);
		sha256_update(&sha_ctx, ipad, 64);
	}

	if ((bytes_read = (int)fread(buffer, 1, 48, infp)) < 48)
	{
		if (!feof(infp)) { return; }
		else
		{
			if ((aeshdr.version == 0x00 && bytes_read != 32) ||
				(aeshdr.version >= 0x01 && bytes_read != 33)) {
				return;
			}
			else
			{
				if (aeshdr.version >= 0x01)
				{
					aeshdr.last_block_size = (buffer[0] & 0x0F);
				}

				if (aeshdr.last_block_size != 0) { return; }
			}
			reached_eof = 1;
		}
	}
	head = buffer + 48;
	tail = buffer;

	FILE* outfp;
	_wfopen_s(&outfp, file_path.c_str(), L"wb");

	while (!reached_eof)
	{
		if (head == (buffer + 64)) { head = buffer; }

		if ((bytes_read = (int)fread(head, 1, 16, infp)) < 16)
		{
			if (!feof(infp)) { fclose(outfp); return; }
			else
			{
				if ((aeshdr.version == 0x00 && bytes_read > 0) ||
					(aeshdr.version >= 0x01 && bytes_read != 1)) {
					fclose(outfp);
					return;
				}

				if (aeshdr.version >= 0x01)
				{
					if ((tail + 16) < (buffer + 64))
					{
						aeshdr.last_block_size = (tail[16] & 0x0F);
					}
					else
					{
						aeshdr.last_block_size = (buffer[0] & 0x0F);
					}
				}

				reached_eof = 1;
			}
		}

		if ((bytes_read > 0) || (aeshdr.version == 0x00))
		{
			if (bytes_read > 0) { head += 16; }
			memcpy(buffer2, tail, 16);
			sha256_update(&sha_ctx, tail, 16);
			aes_decrypt(&aes_ctx, tail, tail);

			for (i = 0; i < 16; i++)
			{
				tail[i] ^= IV[i];
			}

			memcpy(IV, buffer2, 16);
			n = ((!reached_eof) || (aeshdr.last_block_size == 0)) ? 16 : aeshdr.last_block_size;
			if ((i = (int)fwrite(tail, 1, n, outfp)) != n) { fclose(outfp); return; }

			tail += 16;
			if (tail == (buffer + 64)) { tail = buffer; }
		}
	}

	sha256_finish(&sha_ctx, digest);
	sha256_starts(&sha_ctx);
	sha256_update(&sha_ctx, opad, 64);
	sha256_update(&sha_ctx, digest, 32);
	sha256_finish(&sha_ctx, digest);

	if (aeshdr.version == 0x00)
	{
		memcpy(buffer2, tail, 16);
		tail += 16;
		if (tail == (buffer + 64)) { tail = buffer; }
		memcpy(buffer2 + 16, tail, 16);
	}
	else
	{
		memcpy(buffer2, tail + 1, 15);
		tail += 16;
		if (tail == (buffer + 64)) { tail = buffer; }
		memcpy(buffer2 + 15, tail, 16);
		tail += 16;
		if (tail == (buffer + 64)) { tail = buffer; }
		memcpy(buffer2 + 31, tail, 1);
	}

	if (memcmp(digest, buffer2, 32)) { fclose(outfp); return; }
	if (fflush(outfp)) { return; }
	fclose(outfp);
}

std::string to_hex(const std::string& input) {
	std::stringstream r;
	r << std::hex << std::setfill('0');
	for (unsigned char c : input) r << std::setw(2) << static_cast<unsigned int>(c);
	return r.str();
}

std::string from_uint(uint32_t sh) {
	std::string re;
	for (int i = 0; i < 4; i++) re += (unsigned char)(sh >> i * 8);
	return re;
}

std::string base64_encrypt(const std::string& msg) {
	static const std::string base64_chars =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	std::string encoded;
	size_t bits = 0;
	int val = 0;

	for (char c : msg) {
		val = (val << 8) + static_cast<unsigned char>(c);
		bits += 8;
		while (bits >= 6) {
			bits -= 6;
			encoded.push_back(base64_chars[(val >> bits) & 0x3F]);
		}
	}

	if (bits > 0) {
		val <<= 6 - bits;
		encoded.push_back(base64_chars[val & 0x3F]);
	}

	while (encoded.size() % 4 != 0) {
		encoded.push_back('=');
	}

	return encoded;
}

std::string base64_decrypt(const std::string& enc_msg) {
	static const std::string base64_chars =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	std::vector<unsigned char> decoded;
	size_t bits = 0;
	int val = 0;

	for (char c : enc_msg) {
		if (c == '=') {
			break;
		}

		val = (val << 6) + base64_chars.find(c);
		bits += 6;

		if (bits >= 8) {
			bits -= 8;
			decoded.push_back((val >> bits) & 0xFF);
		}
	}

	return std::string(decoded.begin(), decoded.end());
}

std::string bFish_decrypt(const std::string& _msg_enc, const std::string& _key)
{
	std::string _ent(_msg_enc);
	std::string cipher("");
	BlowFish blowfish(_key.c_str(), _key.length());

	int blockSize = 8;
	int rem = _ent.size() % blockSize;
	int padding = (rem == 0) ? 0 : (blockSize - rem);
	_ent += std::string(padding, 0);

	uint32_t lm, rm;
	for (size_t i = 0; i < _ent.size(); i += blockSize)
	{
		lm = 0;
		rm = 0;
		std::string block = _ent.substr(i, blockSize);
		size_t halfSize = block.size() / 2;

		memcpy(&lm, block.substr(0, halfSize).c_str(), 4);
		memcpy(&rm, block.substr(halfSize).c_str(), 4);

		blowfish.decrypt(lm, rm);
		cipher += from_uint(lm) + from_uint(rm);
	}

	size_t nullpos = cipher.find_first_of('\0');
	if (nullpos != std::string::npos) { cipher.erase(nullpos); }

	return cipher;
}

std::string bFish_encrypt(const std::string& msg, const std::string& _key)
{
	std::string _ent(msg);
	std::string cipher("");
	BlowFish blowfish(_key.c_str(), _key.length());

	int blockSize = 8;
	int rem = _ent.size() % blockSize;
	int padding = (rem == 0) ? 0 : (blockSize - rem);
	_ent += std::string(padding, 0);

	uint32_t lm, rm;
	for (size_t i = 0; i < _ent.size(); i += blockSize)
	{
		lm = 0;
		rm = 0;
		std::string block = _ent.substr(i, blockSize);
		size_t halfSize = block.size() / 2;

		memcpy(&lm, block.substr(0, halfSize).c_str(), 4);
		memcpy(&rm, block.substr(halfSize).c_str(), 4);

		blowfish.encrypt(lm, rm);
		cipher += from_uint(lm) + from_uint(rm);
	}

	return cipher;
}

std::string sha256_hash_str(const std::string& input)
{
	unsigned char digest[SHA256_DIGEST_LENGTH];
	sha256_context ctx;
	sha256_starts(&ctx);
	sha256_update(&ctx, input.data(), input.size());
	sha256_finish(&ctx, digest);

	std::string output;
	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) output += digest[i];
	return output;
}

std::string sha512_hash_str(const std::string& input)
{
	unsigned char digest[SHA512_DIGEST_LENGTH];
	sha512_context ctx;
	sha512_starts(&ctx);
	sha512_update(&ctx, input.data(), input.size());
	sha512_finish(&ctx, digest);

	std::string output;
	for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) output += digest[i];
	return output;
}

BOOL exists(const std::wstring& path) {
	WIN32_FILE_ATTRIBUTE_DATA tmp;
	return GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &tmp);
}

std::string w2c(const std::wstring& wstr) {
	std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> converter;
	return converter.to_bytes(wstr);
}

std::wstring c2w(const std::string& str) {
	std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> converter;
	return converter.from_bytes(str);
}

std::string sha256_hash_file(const std::wstring& path)
{
	std::ifstream file(path, std::ios::binary);
	if (!file.is_open()) return "failed";

	sha256_context ctx;
	sha256_starts(&ctx);

	const size_t bufferSize = 4096;
	char buffer[bufferSize];

	while (file.good()) {
		file.read(buffer, bufferSize);
		sha256_update(&ctx, buffer, file.gcount());
	}
	file.close();

	unsigned char digest[SHA256_DIGEST_LENGTH];
	sha256_finish(&ctx, digest);

	std::stringstream ss;
	for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
		ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(digest[i]);
	}

	return ss.str();
}

std::string sha512_hash_file(const std::wstring& path)
{
	std::ifstream file(path, std::ios::binary);
	if (!file.is_open()) return "failed";

	sha512_context ctx;
	sha512_starts(&ctx);

	const size_t bufferSize = 4096;
	char buffer[bufferSize];

	while (file.good()) {
		file.read(buffer, bufferSize);
		sha512_update(&ctx, buffer, file.gcount());
	}
	file.close();

	unsigned char digest[SHA512_DIGEST_LENGTH];
	sha512_finish(&ctx, digest);

	std::stringstream ss;
	for (int i = 0; i < SHA512_DIGEST_LENGTH; ++i) {
		ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(digest[i]);
	}

	return ss.str();
}