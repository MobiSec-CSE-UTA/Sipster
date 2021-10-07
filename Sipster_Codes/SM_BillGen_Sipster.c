#include "pbc.h"
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <openssl/ec.h>      // for EC_GROUP_new_by_curve_name, EC_GROUP_free, EC_KEY_new, EC_KEY_set_group, EC_KEY_generate_key, EC_KEY_free
#include <openssl/ecdsa.h>   // for ECDSA_do_sign, ECDSA_do_verify
#include <openssl/obj_mac.h> // for NID_secp256k1


#include "sdata.h"


 Bill SM_BillGen(int N, Ecdsa ecdsa, Bill bill, Tau_Tk tt){
  if (N==1){
    printf("4. Bill verification phase.\n");
  }

  static unsigned char* ID = "user1";
  unsigned char* elem_bytes = NULL;

  int num_bytes = element_length_in_bytes(tt.R_t);  
  elem_bytes = realloc(elem_bytes,num_bytes);

  int ret = element_to_bytes(elem_bytes, tt.R_t);
  // strcat(elem_bytes, ID);
  // strcat(elem_bytes,"t");

  bill.bill_signature = ECDSA_do_sign(elem_bytes, strlen(elem_bytes), ecdsa.eckey1);
  bill.bill_info  = elem_bytes;

  if (N==1){
    printf(">>>>>SM: bill generated.<<<<<\n");
  }
  free(elem_bytes);
  elem_bytes = NULL;
  return bill;


}

 