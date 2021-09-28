#include "pbc.h"
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <openssl/ec.h>      // for EC_GROUP_new_by_curve_name, EC_GROUP_free, EC_KEY_new, EC_KEY_set_group, EC_KEY_generate_key, EC_KEY_free
#include <openssl/ecdsa.h>   // for ECDSA_do_sign, ECDSA_do_verify
#include <openssl/obj_mac.h> // for NID_secp256k1

#ifndef SDATA_H_INCLUDED
#define SDATA_H_INCLUDED

typedef struct 
  {
    EC_KEY* eckey;
    EC_KEY* eckey1;
  } Ecdsa ;
typedef struct 
  {
    element_t r_t, R_t;
    element_t R_tide[200]; //K=10 for this case
    ECDSA_SIG* signature[200];
    unsigned char* R_tide_char[200];
  } Tau_Tk;
typedef struct 
  {
    element_t R_tide_a[200];
  }Rcpt;  
typedef struct 
  {
    ECDSA_SIG* bill_signature;
    unsigned char* bill_info;
  }Bill; 
typedef struct 
  {

  element_t comb;
  }CombRcpt;

  Ecdsa ecdsa;
  Tau_Tk tt;
  Rcpt rcpt;
  Bill bill;
  CombRcpt combrcpt;

  Tau_Tk SM_TokenGen(int K, element_t g_rnd_uc, pairing_t pairing, Tau_Tk tt, Ecdsa ecdsa);
  Rcpt  UC_ReceiptGen(int K, pairing_t pairing, element_t secret_uc_a,   Tau_Tk tt,  Ecdsa ecdsa,  Rcpt rcpt);

  void RU_Verify(int K, element_t secret_uc_a, element_t g_rnd_uc, element_t ga_uc, pairing_t pairing,  Tau_Tk tt,   Rcpt rcpt);

  Bill SM_BillGen(  Ecdsa ecdsa,  Bill bill,  Tau_Tk tt);

  CombRcpt RU_CombineReceipt(int K,   CombRcpt combrcpt,   Rcpt rcpt,   Tau_Tk tt, element_t ga_uc, pairing_t pairing);

  void UC_Bill_Verify(int K,   Ecdsa ecdsa,   Bill bill,   CombRcpt combrcpt,   Tau_Tk tt, element_t g_rnd_uc, element_t ga_uc, pairing_t pairing);


#endif