#include "textflag.h"

TEXT ·asmEntry(SB), NOSPLIT, $0-0
	CALL ·helper(SB)
	RET
