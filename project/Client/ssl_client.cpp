//----------------------------------------------------------------------------
// File: ssl_client.cpp
// Description: Implementation of an SSL-secured client that performs
//              secure file transfer with a single server over a single
//              connection
//----------------------------------------------------------------------------
#include <string>
#include <time.h>               // to seed random number generator
#include <sstream>          // stringstreams
//added
#include <iostream>
#include <openssl/rand.h>

using namespace std;

#include <openssl/ssl.h>	// Secure Socket Layer library
#include <openssl/bio.h>	// Basic Input/Output objects for SSL
#include <openssl/rsa.h>	// RSA algorithm etc
#include <openssl/pem.h>	// For reading .pem files for RSA keys
#include <openssl/err.h>	// ERR_get_error()
#include <openssl/dh.h>		// Diffie-Helman algorithms & libraries

#include "utils.h"

//----------------------------------------------------------------------------
// Function: main()
//----------------------------------------------------------------------------
int main(int argc, char** argv)
{
  //-------------------------------------------------------------------------
  // Initialization
  
  ERR_load_crypto_strings();
  SSL_library_init();
  SSL_load_error_strings();
  
  setbuf(stdout, NULL); // disables buffered output
  
  // Handle commandline arguments
  // Useage: client server:port filename
  if (argc < 3)
    {
      printf("Useage: client -server serveraddress -port portnumber filename\n");
      exit(EXIT_FAILURE);
    }
  char* server = argv[1];
  char* filename = argv[2];
  
  printf("------------\n");
  printf("-- CLIENT --\n");
  printf("------------\n");
  
  //-------------------------------------------------------------------------
  // 1. Establish SSL connection to the server
  printf("1.  Establishing SSL connection with the server...");
  
  // Setup client context
  SSL_CTX* ctx = SSL_CTX_new(SSLv23_method());
  SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
  //	SSL_CTX_set_options(ctx, SSL_OP_ALL|SSL_OP_NO_SSLv2);
  if (SSL_CTX_set_cipher_list(ctx, "ADH") != 1)
    {
      printf("Error setting cipher list. Sad christmas...\n");
      print_errors();
      exit(EXIT_FAILURE);
    }
  
  // Setup the BIO
  BIO* client = BIO_new_connect(server);
  if (BIO_do_connect(client) != 1)
    {
      printf("FAILURE.\n");
      print_errors();
      exit(EXIT_FAILURE);
    }
  
  // Setup the SSL
  SSL* ssl=SSL_new(ctx);
  if (!ssl)
    {
      printf("Error creating new SSL object from context.\n");
      exit(EXIT_FAILURE);
    }
  SSL_set_bio(ssl, client, client);
  if (SSL_connect(ssl) <= 0)
    {
      printf("Error during SSL_connect(ssl).\n");
      print_errors();
      exit(EXIT_FAILURE);
    }
  
  printf("SUCCESS.\n");
  printf("    (Now connected to %s)\n", server);
  
  //-------------------------------------------------------------------------
  // 2. Send the server a random number
  printf("2.  Sending challenge to the server...");
  /*
  char randomNumber_challenge[129];
  memset(randomNumber_challenge,0,sizeof(randomNumber_challenge));
  int randSize = 128;
  int created_random = RAND_bytes( (unsigned char *)randomNumber_challenge, randSize);
  string randomNumber = randomNumber_challenge;
  */  
string randomNumber="31337";
  //string randomNumber="31333333";
  //SSL_write
  int sent = SSL_write(ssl,(const void*) randomNumber.c_str(),sizeof(randomNumber));
  
  printf("SUCCESS.\n");
  printf("    (Challenge sent: \"%s\")\n", buff2hex((const unsigned char*)randomNumber.c_str(),sizeof(randomNumber)).c_str());
  
  //-------------------------------------------------------------------------
  // 3a. Receive the signed key from the server
  printf("3a. Receiving signed key from server...");

  string signature ="FIXME";
  int siglen = 5;
  //SSL_read;
  {
     char rsa_enc_buff[BUFFER_SIZE];
     memset(rsa_enc_buff,0,sizeof(rsa_enc_buff));
     int rsa_private_enc = SSL_read(ssl,rsa_enc_buff,BUFFER_SIZE);
     signature = rsa_enc_buff;
     siglen = rsa_private_enc;
     
  }
  printf("RECEIVED.\n");
  printf("    (Signature: \"%s\" (%d bytes))\n", buff2hex((const unsigned char*)signature.c_str(), siglen).c_str(), siglen);
  //-------------------------------------------------------------------------
  // 3b. Authenticate the signed key
  printf("3b. Authenticating key...");
  
  //BIO_new(BIO_s_mem())
  //BIO_write
  //BIO_new_file
  //PEM_read_bio_RSA_PUBKEY
  //RSA_public_decrypt
  //BIO_free
  
  string generated_key="";
  int generated_length = 0;
  string decrypted_key="";
  int decrypted_length = 0;
 
  {
    BIO *hash, *boutfile;
    //generating hash
    boutfile = BIO_new(BIO_s_mem());
    hash = BIO_new(BIO_f_md());
    BIO_set_md(hash,EVP_sha1());
    int actualWritten = BIO_write(boutfile,(const void*) randomNumber.c_str(),sizeof(randomNumber));
    BIO_push(hash,boutfile);
    char mdbuf[BUFFER_SIZE];
    memset(mdbuf,0,sizeof(mdbuf));
    int mdlen = BIO_read(hash,mdbuf,BUFFER_SIZE);
    generated_key = buff2hex((const unsigned char*)mdbuf,mdlen);
    generated_length = mdlen;
    int hash_flush = BIO_flush(hash);
    int boutfile_flush = BIO_flush(boutfile);
    print_errors();
  }
  
  {
    BIO  *rsa_public;
    RSA *RSAPUB;
    //decrypting signature given
    char rsa_dec_buff[BUFFER_SIZE];
   rsa_public = BIO_new_file("rsapublickey.pem","r");
   RSAPUB = PEM_read_bio_RSA_PUBKEY(rsa_public,NULL,NULL,NULL);
   int rsa_public_dec = RSA_public_decrypt(siglen,(unsigned char*)signature.c_str(),(unsigned char*)rsa_dec_buff,RSAPUB,RSA_PKCS1_PADDING);
   print_errors();
   decrypted_key = buff2hex((const unsigned char*) rsa_dec_buff,rsa_public_dec);
   decrypted_length = rsa_public_dec;
   int rsa_public_flush = BIO_flush(rsa_public);
 }
  
  printf("AUTHENTICATED\n");
  printf("    (Generated key(SHA1 hash): %s\" (%d bytes))\n", generated_key.c_str(),generated_length);
  printf("    (Decrypted key(SHA1 hash): %s\" (%d bytes))\n", decrypted_key.c_str(),decrypted_length);
  if(generated_key != decrypted_key){
    cerr << "Generated key is not the same as the Decrypted key." 
	 << endl
	 << "Authentication failure between client and server."
	 << endl << "Exiting with error code -1";
    exit(-1);
  }
  else
    cout << "Genratred key matches Decrypted key." 
	 << endl
	 << "Authentication is a success proceeding with further "
	 << "request(s)." << endl;

  //-------------------------------------------------------------------------
  // 4. Send the server a file request
  printf("4.  Sending file request to server...");
  
  PAUSE(2);
  //BIO_flush
  //BIO_puts
  //SSL_write
  
  //BIO_flush in part 3b so not needed here
  int file_request = 0;
  //int file_request = SSL_write(ssl,(const void*)filename,sizeof(filename));
  BIO *request;
  request = BIO_new(BIO_s_mem());
  char filename_to_send[BUFFER_SIZE];
  memset(filename_to_send,0,sizeof(filename_to_send));
  int puts = BIO_puts(request,(const char*)filename);
  int pushed_to_request = BIO_read(request,filename_to_send,puts);
  //cout << "?" <<filename_to_send <<"?"<< endl;
  file_request = SSL_write(ssl,(const void*) filename_to_send,
			   pushed_to_request);
  //flush BIO request
  int flush_request = BIO_flush(request);
  
  print_errors();
  printf("SENT.\n");
  printf("    (File requested: \"%s\" (%d bytes))\n", 
	 filename,file_request);
  
  //-------------------------------------------------------------------------
  // 5. Receives and displays the contents of the file requested
  printf("5.  Receiving response from server...");
  
  //BIO_new_file
  //SSL_read
  //BIO_write
  //BIO_free
  //checking to see if server has any problems with opening 
  //requested file
  {
    char check_buff[BUFFER_SIZE];
    memset(check_buff,0,sizeof(check_buff));
    int check_error_received = SSL_read(ssl,check_buff,
					sizeof(check_buff));
    if(string(check_buff) == "OK"){
      cout << endl 
	   <<"Server is able to process file request" << endl;
      //getting data from server
      {
	BIO *fileout;
	fileout = BIO_new_file(filename,"w");
	int flush_server = BIO_flush(client);
	int bytesReceived = 0;
	int bytesWrote = 0;
	char receive_buf[1024];
	memset(receive_buf,0,sizeof(receive_buf));
	int readAmount = 1023;
	int actualRead = 0;
	int actualWritten = 0;
	cout << endl;
	while((actualRead = SSL_read(ssl,receive_buf,readAmount)) >1)
	  {
	    bytesReceived += actualRead;
	    //print what was read from SSL_read
	    cout << receive_buf;
	    actualWritten = BIO_write(fileout,receive_buf,
				      actualRead);
	    bytesWrote += actualWritten;
	    //setting buffer to zero
	    memset(receive_buf,0,sizeof(receive_buf));
	    //finish outputting the file
	  }
	print_errors();
	printf("\nFILE RECEIVED.\n");
	printf("Recieved.\n");
	printf("    (Bytes sent: %d)\n", bytesReceived);
	printf("Wrote to file: %s\n",filename);
	printf("    (Bytes written: %d)\n", bytesWrote);
	int flush_fileout = BIO_flush(fileout);
	int free_fileout  = BIO_free(fileout);
	int free_server_fileout = BIO_flush(client);
      }
    }
    else if(string(check_buff) == "fnf"){
      cout << endl 
	   << "Server is having a problem sending " << filename 
	   << "." << endl
	   << "Associating error as file not found (fnf)." << endl;
      //proceeding with getting data from 
      
    }
    else
      {
	cerr << endl  
	     << "Receiveing unknown ACK<" << check_buff << "> " 
	     <<"from server." << endl
	     << "Exiting program to prevent any loss of data"
	     << " with error -1."
	     << endl;
	exit(-1);
	printf("FILE NOT RECEIVED.\n");
      }
  }
  
  
  //-------------------------------------------------------------------------
  // 6. Close the connection
  printf("6.  Closing the connection...");
  
  //SSL_shutdown
  //1 = good
  //0 = problem call it again
  //-1 = error
  int server_shutdown = SSL_shutdown(ssl);
  print_errors();
  printf("DONE.\n");
  
  printf("\n\nALL TASKS COMPLETED SUCCESSFULLY.\n");
  
  //-------------------------------------------------------------------------
  // Freedom!
  SSL_CTX_free(ctx);
  SSL_free(ssl);
  return EXIT_SUCCESS;
  
}
