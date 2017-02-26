#include <iostream>
#include <string.h>
#include "mbedtls/aes.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"


//---------------generating na AES key-------------------
bool generateAesKey(unsigned char key[32]) {
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_entropy_context entropy;
//	unsigned char key[32];

	//char *pers = "aes generate key";
	int ret;


	mbedtls_entropy_init( &entropy );
	mbedtls_ctr_drbg_init(&ctr_drbg);
//	ret = mbedtls_ctr_drbg_init(( &ctr_drbg, mbedtls_entropy_func, &entropy,
//	                             (unsigned char *) pers, strlen(pers)));
//	if( ( ret =  != 0 )
//	{
//		printf( " failed\n ! mbedtls_ctr_drbg_init returned -0x%04x\n", -ret );
//		goto exit;
//	}

	if( ( ret = mbedtls_ctr_drbg_random( &ctr_drbg, key, 32 ) ) != 0 )
	{
		printf( " failed\n ! mbedtls_ctr_drbg_random returned -0x%04x\n", -ret );
		//goto exit;
		return false;
	}
	return true;
}

void getRandomVector(unsigned char iv[16]) {
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_entropy_context entropy;
	mbedtls_entropy_init( &entropy );
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_ctr_drbg_random( &ctr_drbg, iv, 16);
}

//---------------Declare the variables needed for AES encryption.-------------

bool encryptData() {
	mbedtls_aes_context aes;

	unsigned char key[32];
	generateAesKey(key);

	unsigned char iv[16];
	getRandomVector(iv);

	unsigned char input [128];
	unsigned char output[128];

	size_t input_len = 40;
	size_t output_len = 0;

	mbedtls_aes_setkey_enc( &aes, key, 256 );
	mbedtls_aes_crypt_cbc( &aes, MBEDTLS_AES_ENCRYPT, 24, iv, input, output );  //TODO puvodne tam bylo jen AES_ENCRYPT?

	return true;
}





int main() {
	std::string inputFilePath;
	std::string outputFilePath;

	std::cout << "Path to the input file:";
	std::cin >> inputFilePath;
	std::cout << "Path to the output file:";
	std::cin >> outputFilePath;


	return 0;
}