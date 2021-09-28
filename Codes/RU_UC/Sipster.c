#include "pbc.h"
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <openssl/ec.h>      // for EC_GROUP_new_by_curve_name, EC_GROUP_free, EC_KEY_new, EC_KEY_set_group, EC_KEY_generate_key, EC_KEY_free
#include <openssl/ecdsa.h>   // for ECDSA_do_sign, ECDSA_do_verify
#include <openssl/obj_mac.h> // for NID_secp256k1
#include "sdata.h"
 



void main(int argc, char **argv)
{
  printf("Please select the algorithm phase.\n");
  printf("Enter 1 for bill settlement phase\n");
  printf("Enter 2 for bill verification phase\n");
  int alg_select = 1;
  scanf("%d", &alg_select); 

  if (alg_select>3){
    printf("Wrong number entered.\n");
    exit(0);
  }

  printf("Please enter the number of tokens (i.e., K) for SMs.\n");

  int K=10; //set the number of bills 
  scanf("%d", &K); 

  double ru_uc_runtime = 0.0;
  clock_t start; clock_t stop;
  

  // Initialize the pairing params
  pbc_param_t par;
  pairing_t pairing;
  pbc_param_init_a_gen(par, 256, 512);
  pairing_init_pbc_param(pairing, par);

  //Initialize ECDSA keys
  ecdsa.eckey=EC_KEY_new();
  ecdsa.eckey1=EC_KEY_new();

  //Publish public parameters by UC
  element_t g_rnd_uc, secret_uc_a, ga_uc;
  element_init_G1(g_rnd_uc,pairing);
  element_init_Zr(secret_uc_a,pairing);
  element_init_G1(ga_uc,pairing);
  element_random(g_rnd_uc);
  element_random(secret_uc_a);    
  element_pow_zn(ga_uc,g_rnd_uc,secret_uc_a);

  

  //Initialize internal states by SM
  element_init_G1(tt.R_t,pairing);element_init_Zr(tt.r_t,pairing);
  element_set0(tt.r_t); element_set1(tt.R_t);
  

   
  //Initilize the ECDSA: (sk_{SM,1},vk_{SM,1}.
  EC_GROUP* ecgroup;
  if (NULL == ecdsa.eckey)
    {
        printf("Failed to create new EC Key\n");
    }
    else
    {
        ecgroup= EC_GROUP_new_by_curve_name(NID_secp256k1);
        if (NULL == ecgroup)
        {
            printf("Failed to create new EC Group\n");
        }
        else
        {
            int set_group_status = EC_KEY_set_group(ecdsa.eckey,ecgroup);
            const int set_group_success = 1;
            if (set_group_success != set_group_status)
            {
                printf("Failed to set group for EC Key\n");
               
            }
            else
            {
                const int gen_success = 1;
                int gen_status = EC_KEY_generate_key(ecdsa.eckey);
                if (gen_success != gen_status)
                {
                    printf("Failed to generate EC Key\n");
                }
            }
           
        }
    }
  printf("############### Algorithm begins ###############\n");
  printf("1. Setup phase completed. \n");



  //Bill issuing phase. Generate tokens according to real-time comsumptions.
  tt = SM_TokenGen(K,g_rnd_uc,pairing,tt,ecdsa);

  //Bill settlement phase. UC settles the tokens offered by RU and generate receipts.
  if(alg_select==1){
    start = clock();
    rcpt = UC_ReceiptGen(K, pairing,secret_uc_a,tt,ecdsa,rcpt);  
    RU_Verify(K, secret_uc_a, g_rnd_uc,  ga_uc, pairing,tt,rcpt);
    stop=clock();
    ru_uc_runtime=(double)(stop-start)*1000/CLOCKS_PER_SEC;  
    printf("Computation time of bill settlement phase: %f ms\n",ru_uc_runtime); 
    exit(0);
  }else{
    rcpt = UC_ReceiptGen(K, pairing,secret_uc_a,tt,ecdsa,rcpt);  
    RU_Verify(K, secret_uc_a, g_rnd_uc,  ga_uc, pairing,tt,rcpt);
  }
  

  EC_GROUP_free(ecgroup);
  EC_KEY_free(ecdsa.eckey);

  //Initilize the ECDSA: (sk_{SM,2},vk_{SM,2}.
  if (NULL == ecdsa.eckey1)
    {
        printf("Failed to create new EC Key\n");
    }
    else
    {
        ecgroup= EC_GROUP_new_by_curve_name(NID_secp256k1);
        if (NULL == ecgroup)
        {
            printf("Failed to create new EC Group\n");
        }
        else
        {
            int set_group_status = EC_KEY_set_group(ecdsa.eckey1,ecgroup);
            const int set_group_success = 1;
            if (set_group_success != set_group_status)
            {
                printf("Failed to set group for EC Key\n");
               
            }
            else
            {
                const int gen_success = 1;
                int gen_status = EC_KEY_generate_key(ecdsa.eckey1);
                if (gen_success != gen_status)
                {
                    printf("Failed to generate EC Key\n");
                }
            }
           
        }
    }

  //Bill verification phase: SM generates bills. RU proves the payments by combaining receipts.
  bill = SM_BillGen(ecdsa, bill, tt);
  if(alg_select==2){
    start = clock();
    combrcpt = RU_CombineReceipt(K,combrcpt,rcpt,tt,ga_uc,pairing);
    UC_Bill_Verify(K,ecdsa, bill,combrcpt, tt, g_rnd_uc, ga_uc, pairing);
    stop=clock();
    ru_uc_runtime=(double)(stop-start)*1000/CLOCKS_PER_SEC;  
    printf("Computation time of bill verification phase: %f ms\n",ru_uc_runtime); 
    exit(0);
  }else{
    combrcpt = RU_CombineReceipt(K,combrcpt,rcpt,tt,ga_uc,pairing);
    UC_Bill_Verify(K,ecdsa, bill,combrcpt, tt, g_rnd_uc, ga_uc, pairing);
  }
  
  
}




