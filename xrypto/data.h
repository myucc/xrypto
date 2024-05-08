#pragma once
#include <string>

namespace data
{
	int curr_item = 0;
	int ctab = 1;
	int split_num = 1;
	bool is_hidden = true;
	const char* items[] = { "BlowFish", "BASE64", "SHA256", "SHA512" };

	char keyU[1048];
	char inputU[4096];
	char outputU[4096];
	std::wstring folder_path;
	std::wstring file_path;
}