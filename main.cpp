#include <iostream>
#include <string.h>
#include <fstream>
#include <vector>
#include <cstring>
#include "mbedtls/aes.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/sha512.h"

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
	if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
	                                   (unsigned char *) pers, strlen( pers ) ) ) != 0 )
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

void getRandomVector(unsigned char iv[16]) {
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_entropy_context entropy;
	mbedtls_entropy_init( &entropy );
	mbedtls_ctr_drbg_init(&ctr_drbg);
	char *pers = "aes generate ivv";
	mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
	                       (unsigned char *) pers, strlen( pers ));
	mbedtls_ctr_drbg_random( &ctr_drbg, iv, 16);
}

//---------------Declare the variables needed for AES encryption.-------------

bool encryptData(std::ifstream* inputFile, std::ofstream* outputFile) {
	mbedtls_aes_context aes;

	unsigned char key[32];
	generateAesKey(key);
	mbedtls_aes_setkey_enc( &aes, key, 256 );
	std::ofstream keyFile("outputs/encryptKey.key", std::ios::out | std::ios::binary | std::ios::trunc);
	keyFile.write(reinterpret_cast<char *> (key),32);
	keyFile.close();

	unsigned char iv[16];
	getRandomVector(iv);
	std::ofstream ivFile("outputs/initzializationVector.key", std::ios::out | std::ios::binary | std::ios::trunc);
	ivFile.write(reinterpret_cast<char *> (iv),16);
	ivFile.close();

	long int inputLen = sizeOfInputFile(inputFile);
	inputFile->seekg(0,std::ios::beg);
	char inputChar[16];
	unsigned char output[16];

	while (inputLen >= 16) {
		inputFile->read(inputChar,16);
		unsigned char *input = reinterpret_cast<unsigned char *> (inputChar);
		unsigned char* iv2(iv);
		unsigned char tmp[16];
		mbedtls_aes_crypt_cbc( &aes, MBEDTLS_AES_ENCRYPT, 16, iv, input, output );
		mbedtls_aes_crypt_cbc( &aes, MBEDTLS_AES_DECRYPT, 16, iv2, output, tmp );
		std::cout << "input data:" << input << "\nrecrypt data: " << tmp << std::endl;

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

	return true;        //TODO musi byt bool?
}

void decryptData(std::ifstream* inputFile){
	mbedtls_aes_context aes;

	unsigned char* key;
	char keybuffer[32];
	std::ifstream keyFile("outputs/encryptKey.key", std::ios::in | std::ios::binary);
	keyFile.seekg(0,std::ios::beg);
	keyFile.read(keybuffer,32);
	key = reinterpret_cast<unsigned char *> (keybuffer);
	mbedtls_aes_setkey_enc( &aes, key, 256 );


	unsigned char* iv;
	char ivbuffer[16];
	std::ifstream ivFile("outputs/initzializationVector.key", std::ios::in | std::ios::binary);
	ivFile.seekg(0,std::ios::beg);
	ivFile.read(ivbuffer,16);
	iv = reinterpret_cast<unsigned char *> (ivbuffer);

	std::ofstream decryptedData("outputs/decryptData", std::ios::out | std::ios::binary | std::ios::trunc);

	long int inputLen = sizeOfInputFile(inputFile);
	inputFile->seekg(0,std::ios::beg);
	char inputChar[inputLen];
	unsigned char output[inputLen];
	inputFile->read(inputChar,inputLen);
	unsigned char *input = reinterpret_cast<unsigned char *> (inputChar);
	mbedtls_aes_crypt_cbc( &aes, MBEDTLS_AES_DECRYPT, inputLen, iv, input, output);
	decryptedData.write(reinterpret_cast<char *> (output),inputLen);
}

void countHas(std::ifstream* input, unsigned char* output) {
	long int inputLen = sizeOfInputFile(input);
	input->seekg(0,std::ios::beg);
	char inputBuffer[inputLen];
	input->read(inputBuffer,inputLen);

	mbedtls_sha512(reinterpret_cast<unsigned char *> (inputBuffer),inputLen,output,0);
}


void hashData(std::ifstream* input) {
	unsigned char output[64];
	countHas(input,output);
	std::ofstream hashFile("outputs/dataHash.hash", std::ios::out | std::ios::binary | std::ios::trunc);
	hashFile.write(reinterpret_cast<char *> (output),64);
}

void verifyHash(std::ifstream* input, unsigned char* origHash) {
	std::cout << "Verifying hash: ";
	unsigned char countedHash[64];
	countHas(input,countedHash);

	if(std::memcmp(countedHash,origHash,64)==0) {
		std::cout << "OK." << std::endl;
	} else {
		std::cout << "NOK." << std::endl;
	}

}




int main() {
	std::string inputFilePath;

	std::string outputFilePath;

	//std::cout << "Path to the input file:";
	//std::cin >> inputFilePath;
	//std::ifstream inputFile(inputFilePath, std::ios::in | std::ios::binary);
	std::ifstream inputFile("input.txt", std::ios::in | std::ios::binary);

	//std::cout << "Path to the output file:";
	//std::cin >> outputFilePath;
	std::ofstream outputFile("outputs/output", std::ios::out | std::ios::binary | std::ios::trunc);
	//todo some fails?
	//if(!inputFile.is_open())

	encryptData(&inputFile,&outputFile);
	hashData(&inputFile);
	outputFile.close();
	std::ifstream dataDec("outputs/output", std::ios::in | std::ios::binary);
	decryptData(&dataDec);


	return 0;
}