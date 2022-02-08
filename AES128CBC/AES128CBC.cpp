#include <unordered_map>
#include <memory.h>
#include "AES128CBC.h"

#define ADD_ROUND_KEY(dwState, dwRoundKey, countMax) __asm					\
{																			\
	__asm mov ecx, 0																\
	__asm mov edx, countMax														\
	__asm mov esi, [dwState]														\
	__asm mov edi, [dwRoundKey]													\
	__asm 																		\
	__asm FORLOOP:																\
	__asm mov eax, [esi + ecx * TYPE char* 4]										\
	__asm mov ebx, [edi + ecx * TYPE char* 4]										\
	__asm xor eax, ebx															\
	__asm mov[esi + ecx * TYPE char* 4], eax										\
	__asm 																		\
	__asm add ecx, 1																\
	__asm cmp ecx, edx															\
	__asm jl FORLOOP																\
}

const BYTE AES128CBC::s[] =
{
	0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
	0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
	0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
	0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
	0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
	0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
	0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
	0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
	0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
	0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
	0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
	0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
	0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
	0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
	0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
	0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

const BYTE AES128CBC::inv_s[] =
{
	0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
	0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
	0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
	0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
	0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
	0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
	0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
	0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
	0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
	0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
	0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
	0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
	0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
	0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
	0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

const uint32_t AES128CBC::blockLength = 16;

uint32_t AES128CBC::roundNum = 9;

const BYTE AES128CBC::header[] = { 0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB };

const uint32_t AES128CBC::headerLength = 16;

bool AES128CBC::Encrypt(
	void* text,
	uint32_t textLength,
	void* keytext,
	uint32_t keyLength,
	void* iv,
	uint32_t ivLength,
	BYTE*& result,
	uint32_t& resultLength
)
{
	std::unique_ptr<BYTE[]> expandedKey(ExpandKey((BYTE*)keytext));
	std::unique_ptr<BYTE[]> ivs(ZeroPadding((BYTE*)iv, ivLength, blockLength));

	int resLen = textLength % blockLength == 0 ? textLength : (textLength / blockLength + 1) * blockLength;
	std::unique_ptr<BYTE[]> totalEnc = std::make_unique<BYTE[]>(resLen);

	for (int part = 0; part < (textLength + blockLength - 1) / blockLength; part++)
	{
		int from = part * blockLength;
#ifdef _WIN32
		int cutoff = min((int)textLength, (int)((part + 1) * blockLength));
#else
		int cutoff = std::min((int)textLength, (int)((part + 1) * blockLength));
#endif
		std::unique_ptr<BYTE[]> subStr = std::make_unique<BYTE[]>(blockLength + 1);
		BYTE* src = ((BYTE*)text) + from;
		BYTE* des = (BYTE*)(subStr.get());
		memcpy(des, src, cutoff - from);

		std::unique_ptr<BYTE[]> partString(ZeroPadding(subStr.get(), cutoff - from, blockLength));
		AddSalt(partString.get(), blockLength, ivs.get(), blockLength);
		Encrypt16Byte(partString.get(), expandedKey.get());
		memcpy(totalEnc.get() + (part * blockLength), partString.get(), blockLength);

		memcpy(ivs.get(), partString.get(), blockLength);
	}
	resultLength = resLen;
	if (result == NULL)
	{
		result = new BYTE[resultLength];
	}
	memcpy(result, totalEnc.get(), resultLength);
	return true;
}

bool AES128CBC::Decrypt(
	void* ciphertext,
	uint32_t ciphertextLength,
	void* keytext,
	uint32_t keyLength,
	void* iv,
	uint32_t ivLength,
	BYTE*& result,
	uint32_t& resultLength
)
{
	if (ciphertextLength % blockLength != 0)
	{
		return false;
	}

	std::unique_ptr<BYTE[]> expandedKey(ExpandKey((BYTE*)keytext));
	std::unique_ptr<BYTE[]> ivs(ZeroPadding((BYTE*)iv, ivLength, blockLength));

	int resLen = ciphertextLength;
	std::unique_ptr<BYTE[]> totalDec = std::make_unique<BYTE[]>(resLen);

	int lastPart = (ciphertextLength + blockLength - 1) / blockLength - 1;
	int from = lastPart * blockLength;
#ifdef _WIN32
	int cutoff = min((int)ciphertextLength, (int)((lastPart + 1) * blockLength));
#else
	int cutoff = std::min((int)ciphertextLength, (int)((lastPart + 1) * blockLength));
#endif
	std::unique_ptr<BYTE[]> subStr = std::make_unique<BYTE[]>(blockLength + 1);
	BYTE* src = ((BYTE*)ciphertext) + from;
	BYTE* des = (BYTE*)(subStr.get());
	memcpy(des, src, cutoff - from);

	BYTE* saltPtr = nullptr;
	for (int part = (ciphertextLength + blockLength - 1) / blockLength - 1; part >= 0; part--)
	{
		if (part >= 1)
		{
			saltPtr = ((BYTE*)ciphertext) + (part - 1) * blockLength;
		}

		Decrypt16Byte(subStr.get(), expandedKey.get());
		AddSalt(subStr.get(), blockLength, part >= 1 ? saltPtr : ivs.get(), blockLength);
		memcpy(totalDec.get() + (part * blockLength), subStr.get(), blockLength);

		memcpy(subStr.get(), saltPtr, blockLength);
	}
	resultLength = resLen;
	if (result == NULL)
	{
		result = new BYTE[resultLength];
	}
	memcpy(result, totalDec.get(), resLen);
	return true;
}

BYTE* AES128CBC::string2hex(void* text, uint32_t n)
{
	std::unordered_map<char, int> mp;
	for (int i = 0; i < 10; i++)
	{
		mp[i + '0'] = i;
	}
	for (int i = 0; i < 6; i++)
	{
		mp[i + 'a'] = i + 10;
	}
	BYTE* res = new BYTE[n / 2];
	for (int i = 0; i < n / 2; i++)
	{
		char c1 = ((BYTE*)text)[i * 2];
		char c2 = ((BYTE*)text)[i * 2 + 1];
		int b1 = mp[c1];
		int b2 = mp[c2];
		res[i] = blockLength * b1 + b2;
	}
	return res;
}

std::string AES128CBC::hex2string(BYTE* hex, uint32_t n)
{
	std::unordered_map<char, int> mp;
	for (int i = 0; i < 10; i++)
	{
		mp[i] = i + '0';
	}
	for (int i = 0; i < 6; i++)
	{
		mp[i + 10] = i + 'a';
	}
	std::string res;
	for (int i = 0; i < n; i++)
	{
		int x = hex[i];
		int b1 = mp[x / blockLength];
		int b2 = mp[x % blockLength];
		res += std::string(1, b1) + std::string(1, b2);
	}
	return res;
}


BYTE AES128CBC::gmul(BYTE a, BYTE b)
{
	BYTE p = 0;
	while (a && b) {
		if (b & 1)
			p ^= a;

		if (a & 0x80)
			a = (a << 1) ^ 0x11b; /* x^8 + x^4 + x^3 + x + 1 */
		else
			a <<= 1;
		b >>= 1;
	}
	return p;
}

BYTE AES128CBC::frcon(BYTE i)
{
	if (i == 0)
		return 0x8d;
	BYTE res = 1;
	for (BYTE x = 1; x < i; x++)
	{
		res = gmul(res, 2);
	}
	return res;
}

void AES128CBC::SubWordRotWordXOR(BYTE* tempWord, BYTE i)
{
	BYTE temp = tempWord[0];
	tempWord[0] = tempWord[1];
	tempWord[1] = tempWord[2];
	tempWord[2] = tempWord[3];
	tempWord[3] = temp;

	tempWord[0] = s[tempWord[0]];
	tempWord[1] = s[tempWord[1]];
	tempWord[2] = s[tempWord[2]];
	tempWord[3] = s[tempWord[3]];

	tempWord[0] ^= frcon(i);
	// other 3 bytes are XORed with 0
}

BYTE* AES128CBC::ExpandKey(BYTE* key)
{
	BYTE* expandedKey = new BYTE[176];

	for (int i = 0; i < blockLength; i++)
	{
		expandedKey[i] = key[i];
	}

	int bytesCount = blockLength;
	int rcon_i = 1;
	BYTE temp[4];

	while (bytesCount < 176)
	{
		for (int i = 0; i < 4; i++)
		{
			temp[i] = expandedKey[i + bytesCount - 4];
		}

		if (bytesCount % blockLength == 0)
		{
			SubWordRotWordXOR(temp, rcon_i++);
		}

		for (BYTE a = 0; a < 4; a++)
		{
			expandedKey[bytesCount] = expandedKey[bytesCount - blockLength] ^ temp[a];
			bytesCount++;
		}
	}

	return expandedKey;
}

/*
* Use this implement if the assembly macro can not be compiled on your platform.
*/
//void AES128CBC::AddSubRoundKey(unsigned char* state, unsigned char* roundKey)
//{
//	// Use DWORD to copy, copy 4 byte at the sametime.
//	DWORD* dwState = (DWORD*)state;
//	DWORD* dwRoundKey = (DWORD*)roundKey;
//	for (int i = 0; i < blockLength / sizeof(DWORD); i++) {
//		dwState[i] ^= dwRoundKey[i];
//	}
//}

void AES128CBC::AddSubRoundKey(BYTE* state, BYTE* roundKey)
{
	DWORD* dwState = (unsigned long*)state;
	DWORD* dwRoundKey = (unsigned long*)roundKey;
	DWORD countMax = blockLength / 4;
	ADD_ROUND_KEY(dwState, dwRoundKey, countMax);
}

void AES128CBC::EncSubBytes(BYTE* state)
{
	for (int i = 0; i < blockLength; i++) {
		state[i] = s[state[i]];
	}
}

void AES128CBC::LeftShiftRows(BYTE* state)
{
	BYTE tempState[blockLength];

	/*
	0 4 8  12	-> 0  4  8  12
	1 5 9  13	-> 5  9  13 1
	2 6 10 14	-> 10 14 2  6
	3 7 11 15	-> 15 3  7  11
	*/

	tempState[0] = state[0];
	tempState[1] = state[5];
	tempState[2] = state[10];
	tempState[3] = state[15];

	tempState[4] = state[4];
	tempState[5] = state[9];
	tempState[6] = state[14];
	tempState[7] = state[3];

	tempState[8] = state[8];
	tempState[9] = state[13];
	tempState[10] = state[2];
	tempState[11] = state[7];

	tempState[12] = state[12];
	tempState[13] = state[1];
	tempState[14] = state[6];
	tempState[15] = state[11];

	memcpy(state, tempState, blockLength);
}

void AES128CBC::MixColumns(BYTE* state)
{
	BYTE tempState[blockLength];

	tempState[0] = (BYTE)(gmul(state[0], 2) ^ gmul(state[1], 3) ^ state[2] ^ state[3]);
	tempState[1] = (BYTE)(state[0] ^ gmul(state[1], 2) ^ gmul(state[2], 3) ^ state[3]);
	tempState[2] = (BYTE)(state[0] ^ state[1] ^ gmul(state[2], 2) ^ gmul(state[3], 3));
	tempState[3] = (BYTE)(gmul(state[0], 3) ^ state[1] ^ state[2] ^ gmul(state[3], 2));

	tempState[4] = (BYTE)(gmul(state[4], 2) ^ gmul(state[5], 3) ^ state[6] ^ state[7]);
	tempState[5] = (BYTE)(state[4] ^ gmul(state[5], 2) ^ gmul(state[6], 3) ^ state[7]);
	tempState[6] = (BYTE)(state[4] ^ state[5] ^ gmul(state[6], 2) ^ gmul(state[7], 3));
	tempState[7] = (BYTE)(gmul(state[4], 3) ^ state[5] ^ state[6] ^ gmul(state[7], 2));

	tempState[8] = (BYTE)(gmul(state[8], 2) ^ gmul(state[9], 3) ^ state[10] ^ state[11]);
	tempState[9] = (BYTE)(state[8] ^ gmul(state[9], 2) ^ gmul(state[10], 3) ^ state[11]);
	tempState[10] = (BYTE)(state[8] ^ state[9] ^ gmul(state[10], 2) ^ gmul(state[11], 3));
	tempState[11] = (BYTE)(gmul(state[8], 3) ^ state[9] ^ state[10] ^ gmul(state[11], 2));

	tempState[12] = (BYTE)(gmul(state[12], 2) ^ gmul(state[13], 3) ^ state[14] ^ state[15]);
	tempState[13] = (BYTE)(state[12] ^ gmul(state[13], 2) ^ gmul(state[14], 3) ^ state[15]);
	tempState[14] = (BYTE)(state[12] ^ state[13] ^ gmul(state[14], 2) ^ gmul(state[15], 3));
	tempState[15] = (BYTE)(gmul(state[12], 3) ^ state[13] ^ state[14] ^ gmul(state[15], 2));

	for (int i = 0; i < blockLength; i++) {
		state[i] = tempState[i];
	}
}

void AES128CBC::Encrypt16Byte(BYTE* plaintext, BYTE* expandedKey)
{
	AddSubRoundKey(plaintext, expandedKey);

	for (int i = 1; i <= roundNum; i++) {
		EncSubBytes(plaintext);
		LeftShiftRows(plaintext);
		MixColumns(plaintext);
		AddSubRoundKey(plaintext, expandedKey + (blockLength * i));
	}

	EncSubBytes(plaintext);
	LeftShiftRows(plaintext);
	AddSubRoundKey(plaintext, expandedKey + 160);
}

void AES128CBC::InverseMixColumns(BYTE* state)
{
	BYTE tempState[blockLength];

	tempState[0] = (BYTE)(gmul(state[0], 14) ^ gmul(state[1], 11) ^ gmul(state[2], 13) ^ gmul(state[3], 9));
	tempState[1] = (BYTE)(gmul(state[0], 9) ^ gmul(state[1], 14) ^ gmul(state[2], 11) ^ gmul(state[3], 13));
	tempState[2] = (BYTE)(gmul(state[0], 13) ^ gmul(state[1], 9) ^ gmul(state[2], 14) ^ gmul(state[3], 11));
	tempState[3] = (BYTE)(gmul(state[0], 11) ^ gmul(state[1], 13) ^ gmul(state[2], 9) ^ gmul(state[3], 14));

	tempState[4] = (BYTE)(gmul(state[4], 14) ^ gmul(state[5], 11) ^ gmul(state[6], 13) ^ gmul(state[7], 9));
	tempState[5] = (BYTE)(gmul(state[4], 9) ^ gmul(state[5], 14) ^ gmul(state[6], 11) ^ gmul(state[7], 13));
	tempState[6] = (BYTE)(gmul(state[4], 13) ^ gmul(state[5], 9) ^ gmul(state[6], 14) ^ gmul(state[7], 11));
	tempState[7] = (BYTE)(gmul(state[4], 11) ^ gmul(state[5], 13) ^ gmul(state[6], 9) ^ gmul(state[7], 14));

	tempState[8] = (BYTE)(gmul(state[8], 14) ^ gmul(state[9], 11) ^ gmul(state[10], 13) ^ gmul(state[11], 9));
	tempState[9] = (BYTE)(gmul(state[8], 9) ^ gmul(state[9], 14) ^ gmul(state[10], 11) ^ gmul(state[11], 13));
	tempState[10] = (BYTE)(gmul(state[8], 13) ^ gmul(state[9], 9) ^ gmul(state[10], 14) ^ gmul(state[11], 11));
	tempState[11] = (BYTE)(gmul(state[8], 11) ^ gmul(state[9], 13) ^ gmul(state[10], 9) ^ gmul(state[11], 14));

	tempState[12] = (BYTE)(gmul(state[12], 14) ^ gmul(state[13], 11) ^ gmul(state[14], 13) ^ gmul(state[15], 9));
	tempState[13] = (BYTE)(gmul(state[12], 9) ^ gmul(state[13], 14) ^ gmul(state[14], 11) ^ gmul(state[15], 13));
	tempState[14] = (BYTE)(gmul(state[12], 13) ^ gmul(state[13], 9) ^ gmul(state[14], 14) ^ gmul(state[15], 11));
	tempState[15] = (BYTE)(gmul(state[12], 11) ^ gmul(state[13], 13) ^ gmul(state[14], 9) ^ gmul(state[15], 14));

	memcpy(state, tempState, blockLength);
}

void AES128CBC::RightShiftRows(BYTE* state)
{
	BYTE tempState[blockLength];

	/*
	0 4 8  12	-> 0  4  8  12
	1 5 9  13	-> 13 1  5  9
	2 6 10 14	-> 10 14 2  6
	3 7 11 15	-> 7  11 15 3
	*/

	tempState[0] = state[0];
	tempState[1] = state[13];
	tempState[2] = state[10];
	tempState[3] = state[7];

	tempState[4] = state[4];
	tempState[5] = state[1];
	tempState[6] = state[14];
	tempState[7] = state[11];

	tempState[8] = state[8];
	tempState[9] = state[5];
	tempState[10] = state[2];
	tempState[11] = state[15];

	tempState[12] = state[12];
	tempState[13] = state[9];
	tempState[14] = state[6];
	tempState[15] = state[3];

	memcpy(state, tempState, blockLength);
}

void AES128CBC::DecSubBytes(BYTE* state)
{
	for (int i = 0; i < blockLength; i++) {
		state[i] = inv_s[state[i]];
	}
}

void AES128CBC::Decrypt16Byte(BYTE* cipher, BYTE* expandedKey)
{
	AddSubRoundKey(cipher, expandedKey + 160);
	RightShiftRows(cipher);
	DecSubBytes(cipher);

	for (int i = roundNum; i >= 1; i--) {
		AddSubRoundKey(cipher, expandedKey + (blockLength * i));
		InverseMixColumns(cipher);
		RightShiftRows(cipher);
		DecSubBytes(cipher);
	}

	AddSubRoundKey(cipher, expandedKey);
}

BYTE* AES128CBC::string2hex(std::string text, uint32_t n)
{
	std::unordered_map<char, int> mp;
	for (int i = 0; i < 10; i++)
	{
		mp[i + '0'] = i;
	}
	for (int i = 0; i < 6; i++)
	{
		mp[i + 'a'] = i + 10;
	}
	BYTE* res = new BYTE[n / 2];
	for (int i = 0; i < n / 2; i++)
	{
		char c1 = text.at(i * 2);
		char c2 = text.at(i * 2 + 1);
		int b1 = mp[c1];
		int b2 = mp[c2];
		res[i] = blockLength * b1 + b2;
	}
	return res;
}

BYTE* AES128CBC::ZeroPadding(BYTE* text, uint32_t textLength, uint32_t length)
{
	BYTE* ret = new BYTE[length];

	for (int i = 0; i < length; i++)
	{
		if (i < textLength)
		{
			ret[i] = text[i];
		}
		else
		{
			ret[i] = 0;
		}
	}
	return ret;
}

void AES128CBC::AddSalt(void* text, uint32_t textLength, void* salt, uint32_t saltLength)
{
	// Use DWORD to copy, copy 4 byte at the sametime.
	DWORD* dwText = (DWORD*)text;
	DWORD* dwSalt = (DWORD*)salt;
	for (int i = 0; i < textLength / sizeof(DWORD); i++)
	{
		dwText[i] ^= dwSalt[i];
	}
}

bool AES128CBC::CheckHeader(BYTE* text, uint32_t length)
{
	if (length < blockLength)
	{
		return false;
	}

	for (int i = 0; i < blockLength; i++)
	{
		if (text[i] != header[i])
		{
			return false;
		}
	}
	return true;
}

void AES128CBC::SetRoundNum(uint32_t roundNum)
{
	if (roundNum >= 0)
	{
		AES128CBC::roundNum = roundNum;
	}
}
