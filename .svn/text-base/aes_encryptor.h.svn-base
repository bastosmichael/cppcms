#ifndef CPPCMS_AES_ENCRYPTOR_H
#define CPPCMS_AES_ENCRYPTOR_H

#include <string>
#include <gcrypt.h>
#include "encryptor.h"

namespace cppcms {

namespace aes {

class cipher : public encryptor {
	gcry_cipher_hd_t hd_out;
	gcry_cipher_hd_t hd_in;
	gcry_md_hd_t hd_mac;
	struct aes_hdr {
		char salt[16];
		time_t timeout;
		unsigned size;
	};
public:
	virtual std::string encrypt(std::string const &plain,time_t timeout);
	virtual bool decrypt(std::string const &cipher,std::string &plain,time_t *timeout=NULL) ;
	cipher(std::string key);
	~cipher();
};

} // aes

} // cppcms


#endif

