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
  printf("Please select the Sipster role of this device.\n");
  printf("Enter 1 for SM\n");
  printf("Enter 2 for RU\n");
  printf("Enter 3 for UC\n");
  int device = 1;
  scanf("%d", &device); 
  if (device>4){
    printf("Wrong number entered.\n");
    exit(0);
  }


  printf("Please select the algorithm phase.\n");
  printf("Enter 1 for bill issuing phase.\n");
  printf("Enter 2 for bill settlement phase.\n");
  printf("Enter 3 for bill verification phase.\n");
  printf("Enter 4 for all phases related with this device.\n");

  int alg_select = 1;
  scanf("%d", &alg_select); 

  if (alg_select>4){
    printf("Wrong number entered.\n");
    exit(0);
  }

  if (device==3&&alg_select==1){
    printf("Error! UC does not have a bill issuing phase.\n");
    exit(0);
  }

  if (device==2&&alg_select==1){
    printf("Error! RU does not have a bill issuing phase.\n");
    exit(0);
  }

  if (device==1&&alg_select==2){
    printf("Error! SM does not have a bill settlement phase.\n");
    exit(0);
  }

  printf("Please enter the number of RUs (i.e., N).\n");
  int N = 1; //set the number of RUs.
  scanf("%d", &N); 

  if (device ==1 && N>1){
    printf("N should equals to one. (One SM is only associated with one RU.)\n");
    exit(0);
  }

  if (device ==2 && N>1){
    printf("N should equals to one. (One RU for this device.)\n");
    exit(0);
  }

  printf("Please enter the number of tokens (i.e., K) for SMs.\n");
  int K=10; //set the number of bills 
  scanf("%d", &K); 

  

  double SM_BillGen_time = 0.0;
  double SM_TokenGen_time  = 0.0; double RU_Verify_time  = 0.0;
  double RU_CombineReceipt_time  = 0.0; double UC_ReceiptGen_time = 0.0;
  double UC_Bill_Verify_time = 0.0;

  for (int lp_n = 1; lp_n<N+1;lp_n++){
  printf("Processing the bills of RU@No. %i \n", lp_n);
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
  if(lp_n==1){
    printf("############### Algorithm begins ###############\n");
    printf("1. Setup phase completed. \n");
  }  
  



  //Bill issuing phase. Generate tokens according to real-time comsumptions.

  start = clock();
  tt = SM_TokenGen(K,lp_n, g_rnd_uc,pairing,tt,ecdsa);
  stop=clock();
  SM_TokenGen_time = SM_TokenGen_time+ (double)(stop-start)*1000/CLOCKS_PER_SEC;  
 

  //Bill settlement phase. UC settles the tokens offered by RU and generate receipts.
  start = clock();
  rcpt = UC_ReceiptGen(K, lp_n, pairing,secret_uc_a,tt,ecdsa,rcpt);  
  stop=clock();
  UC_ReceiptGen_time = UC_ReceiptGen_time+(double)(stop-start)*1000/CLOCKS_PER_SEC;  
 

  start = clock();
  RU_Verify(K, lp_n, secret_uc_a, g_rnd_uc,  ga_uc, pairing,tt,rcpt);
  stop=clock();
  RU_Verify_time = RU_Verify_time+(double)(stop-start)*1000/CLOCKS_PER_SEC;  
 

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
  start = clock();
  bill = SM_BillGen(lp_n, ecdsa, bill, tt);
  stop=clock();
  SM_BillGen_time = SM_BillGen_time+(double)(stop-start)*1000/CLOCKS_PER_SEC;  
 

  start = clock();
  combrcpt = RU_CombineReceipt(K, lp_n, combrcpt,rcpt,tt,ga_uc,pairing);
  stop=clock();
  RU_CombineReceipt_time = RU_CombineReceipt_time+(double)(stop-start)*1000/CLOCKS_PER_SEC;  
 

  start = clock();
  UC_Bill_Verify(K,lp_n, ecdsa, bill,combrcpt, tt, g_rnd_uc, ga_uc, pairing);
  stop=clock();
  UC_Bill_Verify_time = UC_Bill_Verify_time+(double)(stop-start)*1000/CLOCKS_PER_SEC;  
 
  
  EC_GROUP_free(ecgroup);
  EC_KEY_free(ecdsa.eckey1);
  }

  if (device==1&&alg_select==1){
    printf("Computation time of SM at bill issuing phase: %f ms\n",SM_TokenGen_time);
  }
  if (device==1 && alg_select==3){
    printf("Computation time of SM at bill verification phase: %f ms\n",SM_BillGen_time);
  }
  if (device==1 && alg_select==4){
    printf("Computation time of SM: %f ms\n",SM_BillGen_time+SM_TokenGen_time);
  }


 
  if (device==2&&alg_select==2){
    printf("Computation time of RU at bill settlement phase: %f ms\n",RU_Verify_time);
  }
  if (device==2 && alg_select==3){
    printf("Computation time of RU at bill verification phase: %f ms\n",RU_CombineReceipt_time);
  }
  if (device==2 && alg_select==4){
    printf("Computation time of RU: %f ms\n",RU_Verify_time+RU_CombineReceipt_time);
  }

  
  if (device==3&&alg_select==2){
    printf("Computation time of UC at bill settlement phase: %f ms\n",UC_ReceiptGen_time);
  }
  if (device==3 && alg_select==3){
    printf("Computation time of UC at bill verification phase: %f ms\n",UC_Bill_Verify_time);
  }
  if (device==3 && alg_select==4){
    printf("Computation time of UC: %f ms\n",UC_ReceiptGen_time+UC_Bill_Verify_time);
  }


  
  
}




