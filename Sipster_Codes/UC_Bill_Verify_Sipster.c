#include "pbc.h"
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <openssl/ec.h>      // for EC_GROUP_new_by_curve_name, EC_GROUP_free, EC_KEY_new, EC_KEY_set_group, EC_KEY_generate_key, EC_KEY_free
#include <openssl/ecdsa.h>   // for ECDSA_do_sign, ECDSA_do_verify
#include <openssl/obj_mac.h> // for NID_secp256k1


#include "sdata.h"



void UC_Bill_Verify(int K, int N, Ecdsa ecdsa,  Bill bill,  CombRcpt combrcpt,  Tau_Tk tt, element_t g_rnd_uc, element_t ga_uc, pairing_t pairing){

  int verify_status = ECDSA_do_verify(bill.bill_info, strlen(bill.bill_info), bill.bill_signature, ecdsa.eckey1);
  if(verify_status!=1){
    // printf("Signature verification fails.\n");
  }else{
    if (N==1){
      printf(">>>>>UC: bill signature verified.<<<<<\n");
    }
    
  }

  element_t comb_check_right,comb_check_left;
  element_init_GT(comb_check_right,pairing);
  element_init_GT(comb_check_left,pairing);

  pairing_apply(comb_check_left,combrcpt.comb,g_rnd_uc,pairing);   
  pairing_apply(comb_check_right,tt.R_t,ga_uc,pairing);
    
  if(!element_cmp(comb_check_left,comb_check_right) ){
      if (N==1){
        printf(">>>>>UC: bill has been settled.<<<<<\n");
      }
      
      
    }else{
      printf("The receipts are invalid\n");
  }
}
