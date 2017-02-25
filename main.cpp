#include <iostream>
#include "aes.h"
#include "entropy.h"
#include "ctr_drbg.h"


//---------------generating na AES key-------------------
bool generateAesKey(unsigned char key[32]) {
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_entropy_context entropy;
//	unsigned char key[32];

	char *pers = "aes generate key";
	int ret;


}

//---------------Declare the variables needed for AES encryption.-------------
mbedtls_aes_context aes;

//unsigned char key[32];
unsigned char iv[16];

unsigned char input [128];
unsigned char output[128];

size_t input_len = 40;
size_t output_len = 0;




int main() {
	std::cout << "Hello, World!" << std::endl;
	return 0;
}