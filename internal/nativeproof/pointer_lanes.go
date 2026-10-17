package nativeproof

// pointerLane carries one byte's position in a full pointer-word store. The
// zero pointer denotes absent provenance in every instantiation.
type pointerLane[P comparable] struct {
	pointer P
	lane    uint8
}

// orderedPointer admits only all eight matching, correctly ordered lanes.
// Overwriting even one lane with scalar bytes destroys this reconstruction.
func orderedPointer[P comparable](cells []pointerLane[P]) P {
	var zero P
	if len(cells) != 8 || cells[0].pointer == zero {
		return zero
	}
	p := cells[0].pointer
	for j, cell := range cells {
		if cell.pointer != p || cell.lane != uint8(j) {
			return zero
		}
	}
	return p
}
