/****************************************************************************************/
/*
 *  IMSE.CNM_SPIRS_sha2_xl_3.0: sha2_hw.h
 *
 *  Created on: 17/09/2023
 *      Author: camacho@imse-cnm.csic.es
 */
/****************************************************************************************/

#ifndef SHA2_HW_H_INCLUDED
#define SHA2_HW_H_INCLUDED


/************************ MS2XL Constant Definitions **********************/

#if defined(G2RISCV)
  #define MS2XL_BASEADDR 0x60070000
#else
  #define MS2XL_BASEADDR 0x43C30000
#endif

#define MEMORY_DEV_PATH "/dev/mem"
#define MS2XL_LENGTH   0x40

#define RESET					1
#define LOAD					2
#define START					4
#define LOAD_PADDING			8

#define DATA_IN  0x0		/**< data_in */
#define ADDRESS  0x8		/**< address */
#define CONTROL  0x10		/**< control */
#define DATA_OUT 0x18		/**< data_out */
#define END_OP   0x20		/**< end_op */

/************************************* Include Files ************************************/

#include "params.h"
#include "mmio.h"

 #if defined(PYNQ)
  #include <pynq_api.h>
 #endif


/************************ MS2XL Function Definitions **********************/

void sha2_ms2xl_init(MMIO_WINDOW ms2xl, unsigned long long int length, int DBG);
void sha2_ms2xl(unsigned long long int* a, unsigned long long int* b, unsigned long long int length, MMIO_WINDOW ms2xl, int last_hb, int DBG);
void sha2_hw(unsigned char* in, unsigned char* out, unsigned long long int length, MMIO_WINDOW ms2xl, int DBG);

/****************************************************************************************/

#endif // SHA2_HW_H_INCLUDED
