#include "pbc.h"
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <openssl/ec.h>      // for EC_GROUP_new_by_curve_name, EC_GROUP_free, EC_KEY_new, EC_KEY_set_group, EC_KEY_generate_key, EC_KEY_free
#include <openssl/ecdsa.h>   // for ECDSA_do_sign, ECDSA_do_verify
#include <openssl/obj_mac.h> // for NID_secp256k1

#include "sdata.h"


Tau_Tk SM_TokenGen(int K, element_t g_rnd_uc, pairing_t pairing,  Tau_Tk tt,  Ecdsa ecdsa){
  printf("2. Bill issuing phase. \n");

  // Parameters  
  element_t R[K], r[K], g_r[K];

  // Procedures
  for(int i=0;i<K;i++){

    element_init_G1(R[i],pairing);
    element_init_Zr(r[i], pairing);
    element_init_G1(tt.R_tide[i],pairing); 
    element_init_G1(g_r[i],pairing); //Initialize params

    element_random(R[i]); 
    element_random(r[i]);// Choose fresh randomness.

    element_pow_zn(g_r[i],g_rnd_uc,r[i]); 
    element_mul(tt.R_tide[i],g_r[i],R[i]);

    //signature 
    int num_bytes = element_length_in_bytes(tt.R_tide[i]);
    unsigned char *elem_bytes = malloc(num_bytes * sizeof(unsigned char));
    int ret = element_to_bytes(elem_bytes, tt.R_tide[i]);
    tt.signature[i] = ECDSA_do_sign(elem_bytes, strlen(elem_bytes), ecdsa.eckey);
    if (NULL == tt.signature[i]){
      printf("Fail to sign\n");
    }
    tt.R_tide_char[i]= elem_bytes;


    //Update internal states
    element_add(tt.r_t,tt.r_t,r[i]); 
    element_mul(tt.R_t,tt.R_t,R[i]); 

  } 

  element_printf("Updated the internal state r_{tau}: %B\n", tt.r_t);
  element_printf("Updated the internal state R_{tau}: %B\n", tt.R_t);

  printf(">>>>>SM: Token generated.<<<<<.\n");
  return tt;

}
