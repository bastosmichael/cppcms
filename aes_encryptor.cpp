#include <assert.h>
#include <stdio.h>

#include <string>
#include <vector>
#include <algorithm>
#include "cppcms_error.h"
#include "aes_encryptor.h"

#include "base64.h"

#include <pthread.h>
#include <errno.h>

#include <iostream>

GCRY_THREAD_OPTION_PTHREAD_IMPL;

using namespace std;

namespace cppcms {

namespace aes {

namespace {
class load {
	public:
	load() {
		gcry_control (GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
		gcry_check_version(NULL);
		gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
	}
} loader;

} // anon namespace

cipher::cipher(string k) :
	encryptor(k)
{
	unsigned char aes_key[16];
	unsigned char mac_key[20];
	gcry_md_hd_t tmp_mac = 0;
	hd_in = 0;
	hd_out = 0;
	hd_mac = 0;

	if(gcry_md_open(&tmp_mac,GCRY_MD_SHA1,GCRY_MD_FLAG_HMAC) != 0)
		goto error_exit;
	if(gcry_md_setkey(tmp_mac,&key.front(),16) != 0)
		goto error_exit;
	gcry_md_write(tmp_mac,"\0",1);
	memcpy(aes_key,gcry_md_read(tmp_mac,0),16);
	gcry_md_reset(tmp_mac);
	gcry_md_write(tmp_mac,"\1",1);
	memcpy(mac_key,gcry_md_read(tmp_mac,0),16);
	gcry_md_reset(tmp_mac);
	gcry_md_close(tmp_mac);
	tmp_mac = 0;

	if(gcry_cipher_open(&hd_in,GCRY_CIPHER_AES,GCRY_CIPHER_MODE_CBC,0) !=0)
		goto error_exit;
	if(gcry_cipher_open(&hd_out,GCRY_CIPHER_AES,GCRY_CIPHER_MODE_CBC,0) != 0)
		goto error_exit;
	if( gcry_cipher_setkey(hd_in,aes_key,16) != 0)
		goto error_exit;
	if( gcry_cipher_setkey(hd_out,aes_key,16) != 0)
		goto error_exit;
	if(gcry_md_open(&hd_mac,GCRY_MD_SHA1,GCRY_MD_FLAG_HMAC) != 0)
		goto error_exit;
	if(gcry_md_setkey(hd_mac,mac_key,16) != 0)
		goto error_exit;

	memset(aes_key,0,sizeof(aes_key));
	memset(mac_key,0,sizeof(mac_key));
	return;
error_exit:
	if(tmp_mac)
		gcry_md_close(tmp_mac);
	if(hd_mac)
		gcry_md_close(hd_mac);
	if(hd_in)
		gcry_cipher_close(hd_in);
	if(hd_out)
		gcry_cipher_close(hd_out);
	throw cppcms_error("AES cipher initialization failed");
}

cipher::~cipher()
{
	gcry_cipher_close(hd_in);
	gcry_cipher_close(hd_out);
	gcry_md_close(hd_mac);
}

string cipher::encrypt(string const &plain,time_t timeout)
{
	char iv[16];
	gcry_create_nonce(iv,sizeof(iv));
	gcry_cipher_setiv(hd_out,iv,sizeof(iv));
	
	size_t block_size=(sizeof(aes_hdr) + plain.size() + 15) / 16 * 16;

	vector<unsigned char> data(block_size + 20,0); // HMAC-SHA1 signature
	aes_hdr hdr=aes_hdr();
	hdr.timeout = timeout;
	hdr.size = plain.size();
	memcpy(&data[0],&hdr,sizeof(hdr));
	memcpy(&data[sizeof(hdr)],plain.c_str(),plain.size());

	gcry_cipher_encrypt(hd_out,&data[0],block_size,NULL,0);
	gcry_md_write(hd_mac,&data[0],block_size);
	memcpy(&data[block_size],gcry_md_read(hd_mac,0),20);
	gcry_md_reset(hd_mac);
	
	return base64_enc(data);
}

bool cipher::decrypt(string const &cipher,string &plain,time_t *timeout)
{
	vector<unsigned char> data;
	base64_dec(cipher,data);
	size_t norm_size=data.size();
	if(norm_size< 20 + sizeof(aes_hdr) || (norm_size-20) % 16 !=0)
		return false;
	size_t signed_size = norm_size - 20;
	gcry_md_write(hd_mac,&data[0],signed_size);
	if(memcmp(gcry_md_read(hd_mac,0),&data[signed_size],20)!=0) {
		gcry_md_reset(hd_mac);
		return false;
	}
	gcry_md_reset(hd_mac);
	gcry_cipher_decrypt(hd_in,&data[0],signed_size,NULL,0);
	gcry_cipher_reset(hd_in);
	aes_hdr hdr;
	memcpy(&hdr,&data[0],sizeof(hdr));

	if(hdr.timeout < time(NULL))
		return false;
	if(hdr.size > signed_size - sizeof(hdr))
		return false;
	if(timeout) 
		*timeout=hdr.timeout;
	plain.assign(reinterpret_cast<char *>(&data[sizeof(hdr)]),hdr.size);
	return true;
}


} // namespace aes

} // namespace cppcms


