#include <iostream>
#include <future>
#include <thread>
#include <windows.h>
#include "AES128CBC.h"
using namespace std;

int main()
{
	string input, output, key, iv;
	cin >> input;
	cin >> key;
	cin >> iv;

	unsigned char* result = nullptr;
	uint32_t resultLength = 0;

	AES128CBC::SetRoundNum(0);
	unique_ptr<unsigned char[]>inputHex(AES128CBC::string2hex((void*)input.c_str(), input.length()));
	unique_ptr<unsigned char[]> keyHex(AES128CBC::string2hex((void*)key.c_str(), key.length()));
	unique_ptr<unsigned char[]> ivHex(AES128CBC::string2hex((void*)iv.c_str(), iv.length()));
	AES128CBC::Encrypt((void*)inputHex.get(), input.length() / 2, (void*)keyHex.get(), key.length() / 2, (void*)ivHex.get(), iv.length() / 2, result, resultLength);
	string resultStr = AES128CBC::hex2string(result, resultLength);
	cout << resultStr << endl;
	AES128CBC::Decrypt((void*)result, resultLength, (void*)keyHex.get(), key.length() / 2, (void*)ivHex.get(), iv.length() / 2, result, resultLength);
	resultStr = AES128CBC::hex2string(result, resultLength);
	cout << resultStr << endl;
	delete[] result;
}