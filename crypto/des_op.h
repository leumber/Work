#ifndef __DES_OP_H__
#define __DES_OP_H__

#define TDES_KEY_LEN        16
#define D3DES_2KEY       (16)
#define D3DES_3KEY       (24)


extern unsigned int des_ecb_encrypt(unsigned char *pout,unsigned char *pdata,unsigned int nlen,unsigned char *pkey);
extern unsigned int des_ecb_decrypt(unsigned char *pout,unsigned char *pdata,unsigned int nlen,unsigned char *pkey);
unsigned int des_cbc_encrypt(unsigned char *pout,unsigned char *pdata,unsigned int nlen,unsigned char *pkey,unsigned char *piv);
unsigned int des_cbc_decrypt(unsigned char *pout,unsigned char *pdata,unsigned int nlen,unsigned char *pkey,unsigned char *piv);


extern unsigned int des3_ecb_encrypt(unsigned char *pout,unsigned char *pdata,unsigned int nlen,unsigned char *pkey,unsigned int klen);
extern unsigned int des3_ecb_decrypt(unsigned char *pout,unsigned char *pdata,unsigned int nlen,unsigned char *pkey,unsigned int klen);
extern unsigned int des3_cbc_encrypt(unsigned char *pout,unsigned char *pdata,unsigned int nlen,unsigned char *pkey,unsigned int klen,unsigned char *piv);
extern unsigned int des3_cbc_decrypt(unsigned char *pout,unsigned char *pdata,unsigned int nlen,unsigned char *pkey,unsigned int klen,unsigned char *piv);

#endif

