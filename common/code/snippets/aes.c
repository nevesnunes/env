#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/err.h>

char oootoken[32];
char ooostate[32];

void handleErrors(void)
{
	ERR_print_errors_fp(stdout);
	exit(1);
}

int aes_decrypt(char* data, int len, char* key, char* iv, char* out)
{
	EVP_CIPHER_CTX* ctx;
	const EVP_CIPHER* type;
	int outm;
	int outl;

	if(!(ctx = EVP_CIPHER_CTX_new()))
		handleErrors();
	type = EVP_aes_256_cbc();
	if(EVP_DecryptInit_ex(ctx, type, 0, key, iv) != 1)
		handleErrors();
	if(EVP_DecryptUpdate(ctx, out, &outl, data, len) != 1)
		handleErrors();
	if(EVP_DecryptFinal_ex(ctx, &out[outl], &outm) != 1)
		handleErrors();

	EVP_CIPHER_CTX_free(ctx);
	return outl + outm;
}

void init_ooostate()
{
	FILE* f;
	int i;

	memset(ooostate, 0, 32);
	f = fopen("state", "rb");
	if(!f) {
		printf("[error] state not found\n");
		exit(1);
	}
	fread(ooostate, 32, 1, f);
	fclose(f);
}

void init_oootoken()
{
	FILE *f;

	memset(oootoken, 0, 32);
	f = fopen("token", "rb");
	if(!f) {
		puts("[error] token not found");
		exit(1);
	}
	fread(oootoken, 32, 1, f);
	fclose(f);
}

void update_ooostate(char* keyword, unsigned int idx)
{
	size_t len;
	int i;
	char hash[32];
	char buf[164];

	assert(strlen(keyword) < 100);
	// printf("unlocking %s (%d)\n", keyword, idx);
	len = strlen(keyword);
	memcpy(buf, oootoken, 32);
	memcpy(buf + 32, keyword, len + 1);
	memcpy(buf + 32 + len, oootoken, 32);
	SHA256(buf, len + 64, hash);
	for(i = 0; i < 32; i++)
		ooostate[i] ^= hash[i];
}


int main(void)
{
	FILE* file;
	size_t flaglen;
	char* flag;
	char zero[32];
	char out[104];

	init_ooostate();
	init_oootoken();

	update_ooostate("unlockbabylock", 0);
	update_ooostate("badr3d1r", 1);
	update_ooostate("verysneaky", 2);
	update_ooostate("leetness", 3);
	update_ooostate("vneooo", 4);
	update_ooostate("eval", 5);
	update_ooostate("ret", 6);
	update_ooostate("n3t", 7);
	update_ooostate("sig", 8);
	update_ooostate("yo", 9);
	update_ooostate("aro", 10);
	update_ooostate("fnx", 11);
	update_ooostate("ifonly", 12);

	file = fopen("flag", "rb");
	if(!file) {
		puts("[error]");
		exit(1);
	}
	fseek(file, 0, 2);
	flaglen = ftell(file);
	fseek(file, 0, 0);
	flag = (char *)malloc(flaglen + 1);
	fread(flag, 1, flaglen, file);
	fclose(file);
	flag[flaglen] = 0;

	out[aes_decrypt(flag + 16, flaglen - 16, ooostate, flag, out)] = 0;
	printf("You are now a certified bash reverser! The flag is %s\n", out);

	return 0;
}
