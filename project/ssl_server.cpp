//----------------------------------------------------------------------------
// File: ssl_server.cpp
// Description: Implementation of an SSL-secured server that performs
//              secure file transfer to a single client over a single
//              connection.
//----------------------------------------------------------------------------
#include <string>
#include <time.h>
//added
#include <iostream>
using namespace std;

#include <openssl/ssl.h>	// Secure Socket Layer library
#include <openssl/bio.h>	// Basic Input/Output objects for SSL
#include <openssl/rsa.h>	// RSA algorithm etc
#include <openssl/pem.h>	// For reading .pem files for RSA keys
#include <openssl/err.h>

#include "utils.h"

//-----------------------------------------------------------------------------
// Function: main()
//-----------------------------------------------------------------------------
int main(int argc, char** argv)
{
    //-------------------------------------------------------------------------
    // initialize
  ERR_load_crypto_strings();
  SSL_load_error_strings();
  SSL_library_init();
  
  setbuf(stdout, NULL); // disables buffered output
  
  // Handle commandline arguments
  // Useage: client -server serveraddress -port portnumber filename
  if (argc < 2)
    {
      printf("Useage: server:portnumber\n");
      exit(EXIT_FAILURE);
    }
  char* port = argv[1];
  
  printf("------------\n");
  printf("-- SERVER --\n");
  printf("------------\n");
  
  //-------------------------------------------------------------------------
  // 1. Allow for a client to establish an SSL connection
  printf("1. Allowing for client SSL connection...");
  
  // Setup DH object and generate Diffie-Helman Parameters
  DH* dh = DH_generate_parameters(128, 5, NULL, NULL);
  int dh_err;
  DH_check(dh, &dh_err);
  if (dh_err != 0)
    {
      printf("Error during Diffie-Helman parameter generation.\n");
      print_errors();
      exit(EXIT_FAILURE);
    }
  
  // Setup server context
  SSL_CTX* ctx = SSL_CTX_new(SSLv23_method());
  SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
  //	SSL_CTX_set_options(ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_SINGLE_DH_USE);
  SSL_CTX_set_tmp_dh(ctx, dh);
  if (SSL_CTX_set_cipher_list(ctx, "ALL") != 1)
    {
      printf("Error setting cipher list. Sad christmas...\n");
      print_errors();
      exit(EXIT_FAILURE);
    }
  
  // Setup the BIO
  BIO* server = BIO_new(BIO_s_accept());
  BIO_set_accept_port(server, port);
  BIO_do_accept(server);
  
  // Setup the SSL
  SSL* ssl = SSL_new(ctx);
  if (!ssl)
    {
      printf("Error creating new SSL object from context.\n");
      print_errors();
      exit(EXIT_FAILURE);
    }
  SSL_set_accept_state(ssl);
  SSL_set_bio(ssl, server, server);
  if (SSL_accept(ssl) <= 0)
    {
      printf("Error doing SSL_accept(ssl).\n");
      print_errors();
      exit(EXIT_FAILURE);
    }
  
  printf("DONE.\n");
  printf("    (Now listening on port: %s)\n", port);
  
  //-------------------------------------------------------------------------
  // 2. Receive a random number (the challenge) from the client
  printf("2. Waiting for client to connect and send challenge...");
  
  //SSL_read
  string challenge="";
  
  int buff_len = 0;
  char buff[BUFFER_SIZE];
  memset(buff,0,sizeof(buff));
  buff_len = SSL_read(ssl,buff,BUFFER_SIZE);    
  challenge = buff;
  cout << endl<< buff << endl;
  printf("DONE.\n");
  printf("    (Challenge: \"%s\")\n", challenge.c_str());
  
  //-------------------------------------------------------------------------
  // 3. Generate the SHA1 hash of the challenge
  printf("3. Generating SHA1 hash...");
 
  //BIO_new(BIO_s_mem());
  //BIO_write
  //BIO_new(BIO_f_md());
  //BIO_set_md;
  //BIO_push;
  //BIO_gets;

 int mdlen=0;
 string hash_string = ""; 
 
 BIO *hash,*boutfile;
 boutfile = BIO_new(BIO_s_mem());
 hash = BIO_new(BIO_f_md());
 BIO_set_md(hash,EVP_sha1());
 int actualWritten = BIO_write(boutfile,buff,buff_len);  
 BIO_push(hash,boutfile); 
 char mdbuf[BUFFER_SIZE];
 memset(mdbuf,0,sizeof(mdbuf));
 mdlen = BIO_read(hash,mdbuf,BUFFER_SIZE);
 hash_string =  buff2hex((const unsigned char*)mdbuf,mdlen);

  printf("SUCCESS.\n");
  printf("    (SHA1 hash: \"%s\" (%d bytes))\n", hash_string.c_str(), mdlen);
  
  //-------------------------------------------------------------------------
  // 4. Sign the key using the RSA private key specified in the
  //     file "rsaprivatekey.pem"
  printf("4. Signing the key...");
  
  //PEM_read_bio_RSAPrivateKey
  //RSA_private_encrypt
  
  int siglen=0;
  string signature = "FIXME"; 
  BIO *rsa_private;
  RSA * RSAPRIV;
  {
    char rsa_enc_buff[BUFFER_SIZE];
    rsa_private = BIO_new_file("rsaprivatekey.pem","r");
    RSAPRIV = PEM_read_bio_RSAPrivateKey(rsa_private,NULL,NULL,NULL);
    int rsa_private_enc = RSA_private_encrypt(mdlen,(unsigned char*)mdbuf,(unsigned char*)rsa_enc_buff,RSAPRIV,RSA_PKCS1_PADDING);
    siglen = rsa_private_enc;
    signature = rsa_enc_buff;
    print_errors();
  }
  printf("DONE.\n");
  printf("    (Signed key length: %d bytes)\n", siglen);
  printf("    (Signature: \"%s\" (%d bytes))\n", buff2hex((const unsigned char*)signature.c_str(), siglen).c_str(), siglen);
  
  //-------------------------------------------------------------------------
  // 5. Send the signature to the client for authentication
  printf("5. Sending signature to client for authentication...");
 
//BIO_flush
  int flush_bout = BIO_flush(boutfile);
  int flush_hash = BIO_flush(hash);
  int flush_rsa = BIO_flush(rsa_private);
  //SSL_write
  int sent_signiture = SSL_write(ssl,(const void*) signature.c_str(),siglen);
  
  // cout << endl << "SENT(sig to client)<"<<sent_signiture <<">" <<endl;
  
    /*  
  //checking signature on server side an seeing if I can decrypt
  {  
    cout << "CHECKING signature on server side to see if it can"
	 << " decrypted" << endl;
    BIO *rsa_public;
    RSA *RSAPUB;
    char rsa_dec_buff[BUFFER_SIZE];
    rsa_public = BIO_new_file("rsapublickey.pem","r");
    RSAPUB = PEM_read_bio_RSA_PUBKEY(rsa_public,NULL,NULL,NULL);
    int rsa_public_dec = RSA_public_decrypt(siglen,(unsigned char*)signature,(unsigned char*)rsa_dec_buff,RSAPUB,RSA_PKCS1_PADDING);
     print_errors();
    cout << endl;
    printf("    (Decrypted key length: %d bytes)\n", rsa_public_dec);
    printf("    (Decrypted key: \"%s\" (%d bytes))\n", buff2hex((const unsigned char*)rsa_dec_buff, rsa_public_dec).c_str(), rsa_public_dec);
    flush_bout = BIO_flush(boutfile);
    flush_hash = BIO_flush(hash);
    flush_rsa = BIO_flush(rsa_private);
    int flush_rsa_dec = BIO_flush(rsa_public);
  }
  */

  printf("DONE.\n");
  
  //-------------------------------------------------------------------------
  // 6. Receive a filename request from the client
  printf("6. Receiving file request from client...");
  
  //SSL_read
  char file[BUFFER_SIZE];
  memset(file,0,sizeof(file));
  int file_len = 0;
  {
    file_len = SSL_read(ssl,file,BUFFER_SIZE);    
  }
  printf("RECEIVED.\n");
  printf("    (File requested: \"%s\" (%d bytes))\n", file,file_len);
  
  //-------------------------------------------------------------------------
  // 7. Send the requested file back to the client (if it exists)
  printf("7. Attempting to send requested file to client...");
  
  PAUSE(2);
  //BIO_flush
  //BIO_new_file
  //BIO_puts(server, "fnf");
  //BIO_read(bfile, buffer, BUFFER_SIZE)) > 0)
  //SSL_write(ssl, buffer, bytesRead);
  
  int bytesSent=0;
  
  printf("SENT.\n");
  printf("    (Bytes sent: %d)\n", bytesSent);
  
  //-------------------------------------------------------------------------
  // 8. Close the connection
  printf("8. Closing connection...");
  
  //SSL_shutdown
  //BIO_reset
  printf("DONE.\n");
  
  printf("\n\nALL TASKS COMPLETED SUCCESSFULLY.\n");
  
  //-------------------------------------------------------------------------
  // Freedom!
  
  BIO_free_all(server);
  return EXIT_SUCCESS;
}
