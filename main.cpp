#include <iostream>
#include <string.h>
#include <fstream>
#include <vector>
#include <cstring>
#include "mbedtls/aes.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/sha512.h"

bool loadKeyDecrypt(mbedtls_aes_context* aes, unsigned char key[32]) {
	std::string keyFilePath;
	std::cout << "Path - key file: ";
	std::cin >> keyFilePath;
	std::ifstream keyFile(keyFilePath, std::ios::in | std::ios::binary);
	if (!keyFile.is_open()) {
		std::cerr << "File " << keyFilePath << "wasn't found." << std::endl;
		return false;
	}

	char keyBuffer[32];
	keyFile.seekg(0,std::ios::beg);
	keyFile.read(keyBuffer,32);
	memcpy(key,reinterpret_cast<unsigned char *> (keyBuffer),32);
	mbedtls_aes_setkey_dec( aes, key, 256 );
	keyFile.close();
	return true;
}


bool loadIvDecrypt(unsigned char iv[16]) {
	std::string ivFilePath;
	std::cout << "Path - initialization vector: ";
	std::cin >> ivFilePath;
	std::ifstream ivFile(ivFilePath, std::ios::in | std::ios::binary);
	if (!ivFile.is_open()) {
		std::cerr << "File " << ivFilePath << "wasn't found" << std::endl;
		return false;
	}

	char ivBuffer[16];
	ivFile.seekg(0,std::ios::beg);
	ivFile.read(ivBuffer,16);
	memcpy(iv,reinterpret_cast<unsigned char *> (ivBuffer),16);
	return true;
}

long int sizeOfInputFile(std::ifstream* file) {
	std::streampos begin;
	std::streampos end;
	std::streampos cur;

	file->seekg(0,std::ios::beg);
	begin = file->tellg();
	file->seekg(0,std::ios::end);
	end = file->tellg();
	file->seekg(cur);
	return end - begin;
}

//---------------generating na AES key-------------------
bool generateAesKey(unsigned char key[32]) {
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_entropy_context entropy;

	char *pers = "aes generate key";
	int ret;
	mbedtls_entropy_init( &entropy );
	mbedtls_ctr_drbg_init(&ctr_drbg);
	if( (ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (unsigned char *) pers, strlen(pers))) != 0 )
	{
		printf( " failed\n ! mbedtls_ctr_drbg_init returned -0x%04x\n", -ret );
		return false;
	}

	if( ( ret = mbedtls_ctr_drbg_random( &ctr_drbg, key, 32 ) ) != 0 )
	{
		printf( " failed\n ! mbedtls_ctr_drbg_random returned -0x%04x\n", -ret );
		return false;
	}
	return true;
}

bool getRandomVector(unsigned char iv[16]) {
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_entropy_context entropy;
	mbedtls_entropy_init( &entropy );
	mbedtls_ctr_drbg_init(&ctr_drbg);
	char *pers = "aes generate ivv";
	int ret;

	if( (ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (unsigned char *) pers, strlen(pers))) != 0 )
	{
		printf( " failed\n ! mbedtls_ctr_drbg_init returned -0x%04x\n", -ret );
		return false;
	}
	if( (ret = mbedtls_ctr_drbg_random( &ctr_drbg, iv, 16)) != 0 )
	{
		printf( " failed\n ! mbedtls_ctr_drbg_random returned -0x%04x\n", -ret );
		return false;
	}
	return true;
}



void encryptData(std::ifstream* inputFile, std::ofstream* outputFile) {
	mbedtls_aes_context aes;

	unsigned char key[32];
	if(!generateAesKey(key)) {
		return;
	}
	mbedtls_aes_setkey_enc( &aes, key, 256 );
	std::ofstream keyFile("outputs/encrypt.key", std::ios::out | std::ios::binary | std::ios::trunc);
	keyFile.write(reinterpret_cast<char *> (key),32);
	keyFile.close();
	std::cout << "File outputs/encrypt.key was created." << std::endl;

	unsigned char iv[16];
	if(!getRandomVector(iv)) {
		return;
	}
	std::ofstream ivFile("outputs/initializationVector", std::ios::out | std::ios::binary | std::ios::trunc);
	ivFile.write(reinterpret_cast<char *> (iv),16);
	ivFile.close();
	std::cout << "File outputs/initializationVector was created." << std::endl;

	long int inputLen = sizeOfInputFile(inputFile);
	inputFile->seekg(0,std::ios::beg);
	char inputChar[16];
	unsigned char input[16];
	unsigned char output[16];

	while (inputLen >= 16) {
		inputFile->read(inputChar,16);
		memcpy(input,reinterpret_cast<unsigned char *> (inputChar),16);
		unsigned char ivv[16];
		memcpy(ivv,iv, 16);
		unsigned char tmp[16];
		mbedtls_aes_crypt_cbc( &aes, MBEDTLS_AES_ENCRYPT, 16, iv, input, output );
		outputFile->write(reinterpret_cast<char *> (output),16);
		inputLen = inputLen-16;
	}

	if (inputLen != 0) {
		unsigned int value = 16 - inputLen;
		inputFile->read(inputChar,inputLen);
		unsigned char *input = reinterpret_cast<unsigned char *> (inputChar);
		for (int i = 0; i < value; i ++) {
			input[inputLen + i] = value;
		}
		mbedtls_aes_crypt_cbc( &aes, MBEDTLS_AES_ENCRYPT, 16, iv, input, output );
		outputFile->write(reinterpret_cast<char *> (output),16);
	}
	//return true;        //TODO musi byt bool?
}

void decryptData(std::ifstream* inputFile){
	mbedtls_aes_context aes;

	unsigned char key[32];
	if(!loadKeyDecrypt(&aes,key)) {
		return;
	}

	unsigned char iv[16];
	if(!loadIvDecrypt(iv)) {
		return;
	}

	std::ofstream decryptedData("outputs/decryptData", std::ios::out | std::ios::binary | std::ios::trunc);

	long int inputLen = sizeOfInputFile(inputFile);
	inputFile->seekg(0,std::ios::beg);
	char inputChar[16];
	unsigned char output[16];
	unsigned char input[16];
	while (inputLen > 16) {
		inputFile->read(inputChar,16);
		memcpy(input,reinterpret_cast<unsigned char *> (inputChar),16);
		mbedtls_aes_crypt_cbc( &aes, MBEDTLS_AES_DECRYPT, 16, iv, input, output );
			decryptedData.write(reinterpret_cast<char *> (output),16);
			inputLen = inputLen-16;
	}

	inputFile->read(inputChar,16);
	memcpy(input,reinterpret_cast<unsigned char *> (inputChar),16);
	mbedtls_aes_crypt_cbc( &aes, MBEDTLS_AES_DECRYPT, 16, iv, input, output );
	unsigned int endData = output[15];
	decryptedData.write(reinterpret_cast<char *> (output),(16-endData));
}

void countHash(std::ifstream* input, unsigned char* output) {
	long int inputLen = sizeOfInputFile(input);
	input->seekg(0,std::ios::beg);
	char inputBuffer[inputLen];
	input->read(inputBuffer,inputLen);

	mbedtls_sha512(reinterpret_cast<unsigned char *> (inputBuffer),inputLen,output,0);
}


void hashData(std::ifstream* input) {
	unsigned char output[64];
	countHash(input,output);
	std::ofstream hashFile("outputs/data.hash", std::ios::out | std::ios::binary | std::ios::trunc);
	hashFile.write(reinterpret_cast<char *> (output),64);
}

void verifyHash(std::ifstream* input, unsigned char* origHash) {
	std::cout << "Verifying hash: ";
	unsigned char countedHash[64];
	countHash(input,countedHash);

	if(std::memcmp(countedHash,origHash,64)==0) {
		std::cout << "OK." << std::endl;
	} else {
		std::cout << "NOK." << std::endl;
	}

}




int main() {
	std::string inputFilePath;

	std::cout << "Path - input file for encryption: ";
	std::cin >> inputFilePath;
	std::ifstream inputFile(inputFilePath, std::ios::in | std::ios::binary);

	std::ofstream outputFile("outputs/output.aes", std::ios::out | std::ios::binary | std::ios::trunc);

	encryptData(&inputFile,&outputFile);
	std::cout << "File outputs/output.aes was created." << std::endl;
	hashData(&inputFile);
	std::cout << "File outputs/data.hash was created." << std::endl;
	outputFile.close();

	std::cout << "Path - input file for the decryption: ";
	std::cin >> inputFilePath;
	std::ifstream dataDec(inputFilePath, std::ios::in | std::ios::binary);
	std::cout << "File outputs/decryptData was created." << std::endl;
	decryptData(&dataDec);
	return 0;
}