#include "textflag.h"

#ifdef WANT
#define NOOP MOVQ AX, AX
#endif

TEXT ·asmEntry(SB), NOSPLIT, $0-0
	RET
