#include "pbc.h"
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <openssl/ec.h>      // for EC_GROUP_new_by_curve_name, EC_GROUP_free, EC_KEY_new, EC_KEY_set_group, EC_KEY_generate_key, EC_KEY_free
#include <openssl/ecdsa.h>   // for ECDSA_do_sign, ECDSA_do_verify
#include <openssl/obj_mac.h> // for NID_secp256k1


#include "sdata.h"



CombRcpt RU_CombineReceipt(int K,  CombRcpt combrcpt,  Rcpt rcpt,  Tau_Tk tt, element_t ga_uc, pairing_t pairing){

  element_t comb_upper,comb_lower;
  element_init_G1(comb_upper,pairing);
  element_init_G1(comb_lower,pairing);
  element_init_G1(combrcpt.comb,pairing);
  element_set1(comb_upper);

  for(int i=0;i<K;i++){      
    element_mul(comb_upper,comb_upper,rcpt.R_tide_a[i]);
  }
  element_pow_zn(comb_lower,ga_uc,tt.r_t);   
  element_div(combrcpt.comb,comb_upper,comb_lower);
  element_printf("Combained receipt K: %B\n", combrcpt.comb);
  printf(">>>>>RU: receipts combained.<<<<<\n");
  return combrcpt;
}

