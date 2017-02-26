#include <iostream>
#include <string.h>
#include <fstream>
#include "mbedtls/aes.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

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
	char *pers = "aes generate iv";
	mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
	                       (unsigned char *) pers, strlen( pers ));
	mbedtls_ctr_drbg_random( &ctr_drbg, iv, 16);
}

//---------------Declare the variables needed for AES encryption.-------------

bool encryptData(std::ifstream* inputFile, std::ofstream* outputFile) {
	mbedtls_aes_context aes;

	unsigned char key[32];
	generateAesKey(key);

	unsigned char iv[16];
	getRandomVector(iv);

	long int input_len = sizeOfInputFile(inputFile);

	//inputFile.read(input,input_len);
	inputFile->seekg(0,std::ios::beg);
	//unsigned char input [16];
	char inputChar[16];
	unsigned char output[16];

	mbedtls_aes_setkey_enc( &aes, key, 256 );

	std::ofstream keyFile("outputs/encryptKey.key", std::ios::out | std::ios::binary | std::ios::trunc);
	keyFile.write(reinterpret_cast<char *> (key),32);
	keyFile.close();

	std::ofstream ivFile("outputs/initzializationVector.key", std::ios::out | std::ios::binary | std::ios::trunc);
	ivFile.write(reinterpret_cast<char *> (iv),32);
	ivFile.close();

	while (input_len >= 16) {
		inputFile->read(inputChar,16);
		unsigned char *input = reinterpret_cast<unsigned char *> (inputChar);
		mbedtls_aes_crypt_cbc( &aes, MBEDTLS_AES_ENCRYPT, 16, iv, input, output );
//		std::cout << "input: " << input << "   output: " << output << std::endl;
		outputFile->write(reinterpret_cast<char *> (output),16);
		input_len = input_len-16;
	}

	if (input_len != 0) {
		unsigned int value = 16 - input_len;
		inputFile->read(inputChar,input_len);
		unsigned char *input = reinterpret_cast<unsigned char *> (inputChar);
		for (int i = 0; i < value; i ++) {
			input[input_len + i] = value;
		}
		mbedtls_aes_crypt_cbc( &aes, MBEDTLS_AES_ENCRYPT, 16, iv, input, output );
		outputFile->write(reinterpret_cast<char *> (output),16);
	}

	return true;        //TODO musi byt bool?
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
	std::ofstream outputFile("outputs/output.crypt", std::ios::out | std::ios::binary | std::ios::trunc);
	//todo some fails?
	//if(!inputFile.is_open())

	encryptData(&inputFile,&outputFile);



	return 0;
}