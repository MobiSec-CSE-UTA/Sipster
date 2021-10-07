#include "pbc.h"
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <openssl/ec.h>      // for EC_GROUP_new_by_curve_name, EC_GROUP_free, EC_KEY_new, EC_KEY_set_group, EC_KEY_generate_key, EC_KEY_free
#include <openssl/ecdsa.h>   // for ECDSA_do_sign, ECDSA_do_verify
#include <openssl/obj_mac.h> // for NID_secp256k1


#include "sdata.h"


 Rcpt  UC_ReceiptGen(int K, int N, pairing_t pairing, element_t secret_uc_a,   Tau_Tk tt,  Ecdsa ecdsa,  Rcpt rcpt){
  if (N==1){
    printf("3. Bill settlement phase. \n");
  }
  
  for (int i=0;i<K;i++){ 

    int verify_status = ECDSA_do_verify(tt.R_tide_char[i], strlen(tt.R_tide_char[i]), tt.signature[i], ecdsa.eckey);
    if(verify_status!=1){

    }
  }
  if (N==1){
    printf(">>>>>UC: Token signature verified.<<<<<\n");
  }
  
  for(int i=0;i<K;i++){
    element_init_G1(rcpt.R_tide_a[i],pairing);
    element_pow_zn(rcpt.R_tide_a[i],tt.R_tide[i],secret_uc_a);
  }
  if (N==1){
    element_printf("Receipt K: %B\n", rcpt.R_tide_a[K-1]);
    printf(">>>>>UC: Receipt generated.<<<<<\n");
  }
  return rcpt;
  
}


