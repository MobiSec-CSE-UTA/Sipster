#include "pbc.h"
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <openssl/ec.h>      // for EC_GROUP_new_by_curve_name, EC_GROUP_free, EC_KEY_new, EC_KEY_set_group, EC_KEY_generate_key, EC_KEY_free
#include <openssl/ecdsa.h>   // for ECDSA_do_sign, ECDSA_do_verify
#include <openssl/obj_mac.h> // for NID_secp256k1


#include "sdata.h"



void RU_Verify(int K, int N, element_t secret_uc_a, element_t g_rnd_uc, element_t ga_uc, pairing_t pairing,  Tau_Tk tt,   Rcpt rcpt){
  int receipt_check=0;
  element_t temp1[K],temp2[K];
  for(int i=0;i<K;i++){  
    element_init_GT(temp1[i],pairing);
    element_init_GT(temp2[i],pairing); 
    pairing_apply(temp1[i],rcpt.R_tide_a[i],g_rnd_uc,pairing);
    pairing_apply(temp2[i],tt.R_tide[i],ga_uc,pairing); 
    if(!element_cmp(temp1[i],temp2[i])){
          receipt_check = receipt_check+1;
        }else{
          printf("The receipts are invalid.\n");
      }

    }
    if(receipt_check==K && N==1){ 
      printf(">>>>>RU: Receipt verified.<<<<< \n");
  }
}