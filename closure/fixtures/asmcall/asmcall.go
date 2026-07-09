package asmcall

import "os"

func asmMacro()

func asmComponentMacro()

func asmLocalJump()

func asmEntry()

func asmJump()

func macroHelper() int {
	_, _ = os.ReadFile("fixture.txt")
	return 4
}

func COMPONENT_HELPER() int {
	return 98
}

func componentHelper() int {
	_, _ = os.ReadFile("fixture.txt")
	return 5
}

func localJumpHelper() int {
	_, _ = os.ReadFile("fixture.txt")
	return 3
}

func helper() int {
	_, _ = os.ReadFile("fixture.txt")
	return 1
}

func jumpHelper() int {
	return 2
}
