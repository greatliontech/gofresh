package asmcall

import "os"

func asmEntry()

func helper() int {
	_, _ = os.ReadFile("fixture.txt")
	return 1
}
