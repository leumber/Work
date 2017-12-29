
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "des.h"
#include "des_op.h"

unsigned int des_ecb_encrypt(unsigned char *pout,unsigned char *pdata,unsigned int nlen,unsigned char *pkey)
{
    unsigned char *tmp;
    unsigned int len,i;
    unsigned char ch = '\0';
    mbedtls_des_context ctx;

    mbedtls_des_setkey_enc( &ctx, pkey );

    len = (nlen / 8 + (nlen % 8 ? 1: 0)) * 8;

	//ch = 8 - nlen % 8;
    for(i = 0;i < nlen;i += 8)
    {
        mbedtls_des_crypt_ecb( &ctx, (pdata + i), (pout + i) );
    }
    if(len > nlen)
    {
		tmp = (unsigned char *)malloc(len);
        i -= 8;
        memcpy(tmp,pdata + i,nlen - i);
        memset(tmp + nlen % 8, ch, (8 - nlen % 8) % 8);
        mbedtls_des_crypt_ecb( &ctx, tmp, (pout + i));
		free(tmp);
    }
	
    mbedtls_des_free( &ctx );
    return len;


}
unsigned int des_ecb_decrypt(unsigned char *pout,unsigned char *pdata,unsigned int nlen,unsigned char *pkey)
{

    unsigned int i;
    mbedtls_des_context ctx;

	if(nlen % 8)
        return 1;

    mbedtls_des_setkey_dec( &ctx, pkey );


    for(i = 0;i < nlen;i += 8)
    {
        mbedtls_des_crypt_ecb(&ctx, (pdata + i), (pout + i));
    }
    mbedtls_des_free( &ctx );
    return 0;

}
unsigned int des_cbc_encrypt(unsigned char *pout,unsigned char *pdata,unsigned int nlen,unsigned char *pkey,unsigned char *piv)
{
    mbedtls_des_context ctx;
    unsigned char iv[8] = {0};
    unsigned char *pivb;

    if(piv == NULL)
		pivb = iv;
    else
    	pivb = piv;

    mbedtls_des_setkey_enc( &ctx, pkey );

    mbedtls_des_crypt_cbc( &ctx, 1, nlen, pivb, pdata, (pout));
	
    mbedtls_des_free( &ctx );
    
    return nlen;


}
unsigned int des_cbc_decrypt(unsigned char *pout,unsigned char *pdata,unsigned int nlen,unsigned char *pkey,unsigned char *piv)
{

    mbedtls_des_context ctx;
    unsigned char iv[8] = {0};
    unsigned char *pivb;

    if(piv == NULL)
		pivb = iv;
    else
    	pivb = piv;

    mbedtls_des_setkey_dec( &ctx, pkey );

    mbedtls_des_crypt_cbc( &ctx, 0, nlen, pivb, pdata, (pout));
	
    mbedtls_des_free( &ctx );
    
    return 0;

}
unsigned int des3_ecb_encrypt(unsigned char *pout,unsigned char *pdata,unsigned int nlen,unsigned char *pkey,unsigned int klen)
{
    unsigned char *tmp;
    unsigned int len,i;
    unsigned char ch = '\0';
    mbedtls_des3_context ctx3;

	if(klen == D3DES_2KEY)
		mbedtls_des3_set2key_enc( &ctx3, pkey );
	else if(klen == D3DES_3KEY)
		mbedtls_des3_set3key_enc( &ctx3, pkey );

    len = (nlen / 8 + (nlen % 8 ? 1: 0)) * 8;

	//ch = 8 - nlen % 8;
    for(i = 0;i < nlen;i += 8)
    {
        mbedtls_des3_crypt_ecb( &ctx3, (pdata + i), (pout + i) );
    }
    if(len > nlen)
    {
		tmp = (unsigned char *)malloc(len);
        i -= 8;
        memcpy(tmp,pdata + i,nlen - i);
        memset(tmp + nlen % 8, ch, (8 - nlen % 8) % 8);
        mbedtls_des3_crypt_ecb( &ctx3, tmp, (pout + i));
		free(tmp);
    }
	
    mbedtls_des3_free( &ctx3 );
    return len;


}
unsigned int des3_ecb_decrypt(unsigned char *pout,unsigned char *pdata,unsigned int nlen,unsigned char *pkey,unsigned int klen)
{

    unsigned int i;
    mbedtls_des3_context ctx3;

	if(nlen % 8)
        return 1;

    if(klen == D3DES_2KEY)
		mbedtls_des3_set2key_dec( &ctx3, pkey );
	else if(klen == D3DES_3KEY)
		mbedtls_des3_set3key_dec( &ctx3, pkey );


    for(i = 0;i < nlen;i += 8)
    {
        mbedtls_des3_crypt_ecb(&ctx3, (pdata + i), (pout + i));
    }
    mbedtls_des3_free( &ctx3 );
    return 0;

}
unsigned int des3_cbc_encrypt(unsigned char *pout,unsigned char *pdata,unsigned int nlen,unsigned char *pkey,unsigned int klen,unsigned char *piv)
{
    mbedtls_des3_context ctx;
    unsigned char iv[8] = {0};
    unsigned char *pivb;

    if(piv == NULL)
		pivb = iv;
    else
    	pivb = piv;

    if(klen == D3DES_2KEY)
		mbedtls_des3_set2key_enc( &ctx, pkey );
	else if(klen == D3DES_3KEY)
		mbedtls_des3_set3key_enc( &ctx, pkey );

    mbedtls_des3_crypt_cbc( &ctx, 1, nlen, pivb, pdata, (pout));
	
    mbedtls_des3_free( &ctx );
    
    return nlen;


}
unsigned int des3_cbc_decrypt(unsigned char *pout,unsigned char *pdata,unsigned int nlen,unsigned char *pkey,unsigned int klen,unsigned char *piv)
{

    mbedtls_des3_context ctx;
    unsigned char iv[8] = {0};
    unsigned char *pivb;

    if(piv == NULL)
		pivb = iv;
    else
    	pivb = piv;


    if(klen == D3DES_2KEY)
		mbedtls_des3_set2key_dec( &ctx, pkey );
	else if(klen == D3DES_3KEY)
		mbedtls_des3_set3key_dec( &ctx, pkey );

    mbedtls_des3_crypt_cbc( &ctx, 0, nlen, pivb, pdata, (pout));
	
    mbedtls_des3_free( &ctx );
    
    return 0;

}