#include <ShlObj.h>
#include <atlbase.h>

#include "data.h"
#include "crypt/doddles.h"

void clean_up()
{
	RtlZeroMemory(data::inputU, sizeof(data::inputU));
	RtlZeroMemory(data::outputU, sizeof(data::outputU));
	data::file_path.clear();
	data::folder_path.clear();
}

void pick_file()
{
	WCHAR pszFilePath[MAX_PATH]{ 0 };
	OPENFILENAMEW ofn{ 0 };
	ofn.lStructSize = sizeof(ofn);
	ofn.hwndOwner = NULL;
	ofn.lpstrFile = pszFilePath;
	ofn.nMaxFile = MAX_PATH;
	ofn.lpstrFilter = L"All Files (*.*)\0*.*\0";
	GetOpenFileNameW(&ofn);
	data::file_path.assign(pszFilePath);
}

void pick_fold()
{
	if (SUCCEEDED(CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE)))
	{
		CComPtr<IFileOpenDialog> pFolderDlg;
		if (SUCCEEDED(CoCreateInstance(CLSID_FileOpenDialog, NULL, CLSCTX_ALL,
			IID_IFileOpenDialog, reinterpret_cast<void**>(&pFolderDlg))))
		{
			FILEOPENDIALOGOPTIONS opt = {};
			pFolderDlg->GetOptions(&opt);
			pFolderDlg->SetOptions(opt | FOS_PICKFOLDERS | FOS_PATHMUSTEXIST | FOS_FORCEFILESYSTEM);

			if (SUCCEEDED(pFolderDlg->Show(NULL)))
			{
				CComPtr<IShellItem> pItem;
				if (SUCCEEDED(pFolderDlg->GetResult(&pItem)))
				{
					LPWSTR pszFilePath;
					if (SUCCEEDED(pItem->GetDisplayName(SIGDN_FILESYSPATH, &pszFilePath)))
					{
						data::folder_path.assign(pszFilePath);
						CoTaskMemFree(pszFilePath);
					}
				}
			}
		}
	}
}

void text_ed(BOOL is_encryption)
{
	std::string _key(data::keyU), _tmp(data::inputU), _data;

	switch (data::curr_item)
	{
	case 0: {
		if (!_tmp.empty() && !_key.empty() && _key.size() >= 4) {
			std::vector<std::string> lines;
			std::istringstream iss(_tmp);
			std::string line;
			while (std::getline(iss, line)) {
				std::string sss;
				if (is_encryption) {
					auto enc_ = bFish_encrypt(line, _key);
					sss = base64_encrypt(enc_);
				}
				else {
					auto dec_ = base64_decrypt(line);
					sss = bFish_decrypt(dec_, _key);
				}
				lines.push_back(sss);
			}

			for (auto& s : lines){
				_data += (s + "\n");
			}
			
			/*if (is_encryption) {
				auto enc_ = bFish_encrypt(_tmp, _key);
				auto enc = base64_encrypt(enc_);
				_data.assign(enc.begin(), enc.end());
			}
			else {
				auto dec_ = base64_decrypt(_tmp);
				auto dec = bFish_decrypt(dec_, _key);
				_data.assign(dec.begin(), dec.end());
			}*/
		}
		break;
	}
	case 1: {
		if (!_tmp.empty()) {
			if (is_encryption) {
				auto enc = base64_encrypt(_tmp);
				_data.assign(enc.begin(), enc.end());
			}
			else {
				auto dec = base64_decrypt(_tmp);
				_data.assign(dec.begin(), dec.end());
			}
		}
		break;
	}
	case 2: {
		if (is_encryption) {
			if (!_tmp.empty()) {
				auto hash = to_hex(sha256_hash_str(_tmp));
				_data.assign(hash.begin(), hash.end());
			}
		}
		break;
	}
	case 3: {
		if (is_encryption) {
			if (!_tmp.empty()) {
				auto hash = to_hex(sha512_hash_str(_tmp));
				_data.assign(hash.begin(), hash.end());
			}
		}
		break;
	}
	default:
		break;
	}

	RtlZeroMemory(data::outputU, sizeof(data::outputU));
	strcpy_s(data::outputU, _data.c_str());
}

void crypt_file(const std::wstring& infile, BOOL is_encryption, BOOL der = FALSE, const std::wstring& fds = L"")
{
	auto _wkey(c2w(data::keyU));
	if (exists(infile) && !_wkey.empty() && _wkey.size() >= 4)
	{
		FILE* infp, * outfp;
		std::wstring new_path, dir_path, suffix, dir;
		size_t pos = infile.find_last_of('\\');
		auto namez = infile.substr(pos + 1);

		if (der) dir.assign(fds);
		else dir.assign(infile.substr(0, pos));

		_wfopen_s(&infp, infile.c_str(), L"rb");
		if (!infp) return;

		if (is_encryption)
		{
			new_path.assign(dir + L"\\" + namez + L"_" + rstring<std::wstring>(3) + L"_enc");
			_wfopen_s(&outfp, new_path.c_str(), L"wb"); if (!outfp) return;
			encrypt_stream(infp, outfp, _wkey.data(), _wkey.size());
			fclose(outfp);
		}
		else
		{
			new_path.assign(dir + L"\\" + namez + L"_" + rstring<std::wstring>(3) + L"_enc");
			decrypt_stream(infp, new_path.c_str(), _wkey.data(), _wkey.size());
		}

		fclose(infp);
	}
}

void eline_ed(BOOL is_encryption)
{
	std::string _key(data::keyU);
	if (_key.empty() || _key.size() < 4) return;
	if (!exists(data::file_path)) return;

	std::ifstream inputFile(data::file_path);
	if (!inputFile.is_open()) return;

	size_t pos = data::file_path.find_last_of('\\');
	auto dir = data::file_path.substr(0, pos);
	auto namez = data::file_path.substr(pos + 1);

	std::ofstream outFile(dir + L"\\" + namez + L"_" + rstring<std::wstring>(3) + L".txt");
	if (!outFile.is_open()) return;

	std::string line;
	while (std::getline(inputFile, line))
	{
		if (line.empty()) continue;

		if (is_encryption)
		{
			auto _fenc = bFish_encrypt(line, _key);
			auto _benc = base64_encrypt(_fenc);
			outFile << _benc << '\n';
		}
		else
		{
			auto _benc = base64_decrypt(line);
			auto _fenc = bFish_decrypt(_benc, _key);
			outFile << _fenc << '\n';
		}
	}

	inputFile.close();
	outFile.close();
}

void dir_ed(BOOL is_encryption)
{
	if (!exists(data::folder_path)) return;
	std::wstring dir{ data::folder_path + L"\\" + rstring<std::wstring>(5) };
	if (fs::create_directory(dir))
	{
		std::vector<std::wstring> fils;
		for (const auto& file : fs::recursive_directory_iterator(data::folder_path))
			if(file.is_regular_file())
				fils.push_back(file.path().wstring());
		
		for (auto& fil : fils)
			crypt_file(fil, is_encryption, TRUE, dir);
	}
}

void hash_f()
{
	std::string _data;
	if (!exists(data::file_path)) return;

	switch (data::curr_item)
	{
	case 2: {
		std::string hash{ sha256_hash_file(data::file_path) };
		_data.assign(hash.begin(), hash.end());
		break;
	}
	case 3: {
		std::string hash{ sha512_hash_file(data::file_path) };
		_data.assign(hash.begin(), hash.end());
		break;
	}
	default:
		break;
	}

	RtlZeroMemory(data::outputU, sizeof(data::outputU));
	strcpy_s(data::outputU, _data.c_str());
}

void split_f()
{
	if (!exists(data::file_path)) return;

	size_t pos = data::file_path.find_last_of('\\');
	auto dir = data::file_path.substr(0, pos);
	auto fuse_path = dir + L"\\splited";

	std::ifstream ifile(data::file_path, std::ios::binary);
	if (!ifile.is_open()) return;

	ifile.seekg(0, std::ios::end);
	size_t fsz = ifile.tellg();
	ifile.seekg(0, std::ios::beg);

	if ((fsz / 1024) < data::split_num) return;

	if (!exists(fuse_path)) {
		if (!CreateDirectoryW(fuse_path.c_str(), nullptr)) return;
	}
	else return;

	char* hebuff = new char[4];
	const size_t chunkSize = 4 * 1024 * 1024;
	size_t cps = fsz / data::split_num;
	size_t lps = fsz - (cps * (data::split_num - 1));
	for (int i = 0; i < data::split_num; ++i) {
		size_t partsize = (i == data::split_num - 1) ? lps : cps;

		auto ofpath = fuse_path + L"\\" + rstring<std::wstring>(5);
		std::ofstream ofile(ofpath, std::ios::binary);
		if (!ofile.is_open()) return;

		char* buffer = new char[partsize];
		ifile.read(buffer, partsize);

		hebuff[0] = 'G';
		hebuff[1] = 'F';
		hebuff[2] = 'M';
		hebuff[3] = i;
		ofile.write(hebuff, 4);

		size_t rnSize = partsize;
		while (rnSize > 0) {
			size_t writeSize = min(chunkSize, rnSize);
			ofile.write(buffer + (partsize - rnSize), writeSize);
			rnSize -= writeSize;
		}
		delete[] buffer;
	}

	delete[] hebuff;
	ifile.close();
}

void merge_f()
{
	struct _fdata {
		int index;
		std::wstring path;
		bool operator<(const _fdata& other) {
			return index < other.index;
		}
	};

	if (!exists(data::folder_path)) return;
	std::wstring outfile(data::folder_path + L"\\" + rstring<std::wstring>(3) + L"_merged");

	char* hebuff = new char[4];
	std::vector<_fdata> arr;
	for (const auto& entry : fs::recursive_directory_iterator(data::folder_path)) {
		if (entry.is_regular_file()) {
			std::ifstream ifile(entry.path().wstring(), std::ios::binary);
			if (!ifile.is_open()) return;
			ifile.read(hebuff, 4);
			if (hebuff[0] != 'G' && hebuff[1] != 'F' && hebuff[2] != 'M') continue;
			arr.push_back(_fdata{ (int)((unsigned char)hebuff[3]), entry.path().wstring() });
			ifile.close();
		}
	}
	delete[] hebuff;

	int n = arr.size();
	for (int i = 0; i < n - 1; ++i) {
		int mi = i;
		for (int j = i + 1; j < n; ++j) if (arr[j] < arr[mi]) mi = j;
		if (mi != i) std::swap(arr[i], arr[mi]);
	}

	std::ofstream ofile(outfile, std::ios::binary);
	if (!ofile.is_open()) return;

	for (const auto& s : arr) {
		std::ifstream ifile(s.path, std::ios::binary);
		if (!ifile.is_open()) return;
		ifile.seekg(4, std::ios::beg);
		std::streampos startPos = ifile.tellg();
		ifile.seekg(0, std::ios::end);
		std::streampos endPos = ifile.tellg();
		std::streamsize fileSize = endPos - startPos;
		ifile.seekg(startPos);
		char* buffer = new char[fileSize];
		ifile.read(buffer, fileSize);
		ofile.write(buffer, fileSize);
		delete[] buffer;
		ifile.close();
	}

	ofile.close();
}

void erase_dir()
{
	if (!exists(data::folder_path)) return;

	if (MessageBoxA(0, "Are you sure?", "", MB_OKCANCEL) == IDOK)
	{
		std::vector<std::wstring> dirs;
		std::vector<std::wstring> fils;
		for (const auto& file : fs::recursive_directory_iterator(data::folder_path))
		{
			if (file.is_regular_file()) {
				fils.push_back(file.path().wstring());
			}
			if (file.is_directory()) {
				dirs.push_back(file.path().wstring());
			}
		}

		std::sort(dirs.begin(), dirs.end(), [](const std::wstring& wcs1, const std::wstring& wcs2) {
			size_t c1 = std::count(wcs1.begin(), wcs1.end(), '\\');
			size_t c2 = std::count(wcs2.begin(), wcs2.end(), '\\');
			return c1 > c2;
			});

		for (auto& fil : fils) {
			std::ofstream outfile(fil, std::ios::out | std::ios::trunc);
			outfile.close();
			auto diz = fil.substr(0, fil.find_last_of('\\'));
			auto new_path = diz + L"\\" + rstring<std::wstring>(5);
			fs::rename(fil, new_path);
			fs::remove(new_path);
		}

		for (auto& dir : dirs) {
			auto diz = dir.substr(0, dir.find_last_of('\\'));
			auto new_path = diz + L"\\" + rstring<std::wstring>(5);
			fs::rename(dir, new_path);
			fs::remove(new_path);
		}

		fs::remove(data::folder_path);
	}
}