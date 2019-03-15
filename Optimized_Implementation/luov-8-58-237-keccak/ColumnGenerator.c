#include "ColumnGenerator.h"

void ColumnGenerator_init(ColumnGenerator * col_gen, const unsigned char* key){
	int i;
	unsigned char stream[16] = {0};

	for(i=0; i<STATES; i++){
		stream[0] = i;
		PRNG_INIT(&col_gen->states[i], key, stream);
	}
	col_gen->cols_used = BLOCK_SIZE/2;
}


column Next_Column(ColumnGenerator *col_gen){
	unsigned char i,j;
	if(col_gen->cols_used == BLOCK_SIZE/2){
		for(i=0; i<STATES; i++){
			PRNG_GET_BLOCK(&col_gen->states[i],col_gen->blocks[i]);
		}
		col_gen->cols_used = 0;
	}

	#if (OIL_VARS <= 64) 
		column Out = 0;
		for(i=0; i<STATES; i++){
			Out |= ((column)col_gen->blocks[i][col_gen->cols_used*2    ]) << 16*i;
			Out |= ((column)col_gen->blocks[i][col_gen->cols_used*2 + 1]) << 16*i+8;
		}
	#else
		column Out = {0};
		for(i=0; i<4; i++){
			Out.components[0] |= ((uint64_t)col_gen->blocks[i][col_gen->cols_used*2    ]) << 16*i;
			Out.components[0] |= ((uint64_t)col_gen->blocks[i][col_gen->cols_used*2 + 1]) << 16*i+8;
		}

		for(; i<STATES; i++){
			Out.components[1] |= ((uint64_t)col_gen->blocks[i][col_gen->cols_used*2 + 0]) << 16*(i-4);
			Out.components[1] |= ((uint64_t)col_gen->blocks[i][col_gen->cols_used*2 + 1]) << 16*(i-4)+8;
		}
	#endif

	col_gen->cols_used ++;
	return Out;
}