#pragma once

#ifndef AES_128_CBC
#define AES_128_CBC

#include <iostream>

#ifdef _WIN32
#include <Windows.h>
#else
typedef unsigned short WORD;
typedef unsigned char  BYTE;
typedef unsigned long DWORD;
#endif

class AES128CBC
{
public:
	static bool Encrypt(
		void* text,
		uint32_t textLength,
		void* keytext,
		uint32_t keyLength,
		void* iv,
		uint32_t ivLength,
		BYTE*& result,
		uint32_t& resultLength
	);
	static bool Decrypt(
		void* ciphertext,
		uint32_t ciphertextLength,
		void* keytext,
		uint32_t keyLength,
		void* iv,
		uint32_t ivLength,
		BYTE*& result,
		uint32_t& resultLength
	);
	static BYTE* string2hex(void* text, uint32_t n);
	static std::string hex2string(BYTE* hex, uint32_t n);
	static bool CheckHeader(BYTE* text, uint32_t length);

	static void SetRoundNum(uint32_t roundNum);

private:
	static const BYTE s[256];
	static const BYTE inv_s[256];
	static const uint32_t blockLength;
	static uint32_t roundNum;
	static const BYTE header[16];
	static const uint32_t headerLength;

	static inline BYTE gmul(BYTE a, BYTE b);
	static BYTE frcon(BYTE i);
	static void SubWordRotWordXOR(BYTE* temp_word, BYTE i);
	static BYTE* ExpandKey(BYTE* key);
	static void AddSubRoundKey(BYTE* state, BYTE* round_key);
	static void EncSubBytes(BYTE* state);
	static void LeftShiftRows(BYTE* state);
	static void MixColumns(BYTE* state);
	static void Encrypt16Byte(BYTE* plaintext, BYTE* expanded_key);
	static void InverseMixColumns(BYTE* state);
	static void RightShiftRows(BYTE* state);
	static void DecSubBytes(BYTE* state);
	static void Decrypt16Byte(BYTE* cipher, BYTE* expanded_key);
	static BYTE* string2hex(std::string text, uint32_t n);
	static BYTE* ZeroPadding(BYTE* text, uint32_t textLength, uint32_t length);
	static void AddSalt(void* text, uint32_t textLength, void* salt, uint32_t saltLength);
};

#endif // !AES_128_CBC