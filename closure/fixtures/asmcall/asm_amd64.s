#include "textflag.h"

#define CALL_MACRO_HELPER CALL ·macroHelper(SB)
#define COMPONENT_HELPER componentHelper

TEXT ·asmComponentMacro(SB), NOSPLIT, $0-0
	CALL ·COMPONENT_HELPER(SB)
	RET

TEXT ·asmMacro(SB), NOSPLIT, $0-0
	CALL_MACRO_HELPER
	RET

TEXT ·asmLocalJump(SB), NOSPLIT, $0-0
	JMP localDone
localDone:
	CALL ·localJumpHelper(SB)
	RET

TEXT ·asmEntry(SB), NOSPLIT, $0-0
	CALL ·helper(SB)
	RET

TEXT ·asmJump(SB), NOSPLIT, $0-0
	JMP ·jumpHelper(SB)
