package nativeproof

// validateMemoryMapping is the common conservative data-mapping policy for
// frame and transition interfaces. It checks permissions and backing-page
// aliases without supplying initial values. Callers establish nonempty canonical
// extents before this check; tick belongs to their cumulative work budget.
func (im *Image) validateMemoryMapping(pc uint64, r ByteRegion, tick func() error) error {
	found := -1
	for j, load := range im.loads {
		if err := tick(); err != nil {
			return err
		}
		if !overlap(pages(r.Bytes), pages(Span{load.va, load.end})) {
			continue
		}
		if !r.Image || r.Bytes.Start < load.va || r.Bytes.End > load.end || r.Readable && !load.readable || r.Writable && (!load.writable || load.executable) {
			return refuse(pc, "frame-mapping", "region conflicts with actual image mapping or permissions")
		}
		found = j
	}
	if r.Image && found < 0 {
		return refuse(pc, "frame-mapping", "image region has no loaded backing")
	}
	if found >= 0 {
		load := im.loads[found]
		// Conservatively reject aliases of the load's file pages, including a
		// BSS load's partial-page prefix. No file contents are assumed constant.
		if load.filesz != 0 || load.off%4096 != 0 {
			file := pages(Span{load.off, load.off + load.filesz})
			for j, alias := range im.loads {
				if err := tick(); err != nil {
					return err
				}
				if j != found && (alias.filesz != 0 || alias.off%4096 != 0) && overlap(file, pages(Span{alias.off, alias.off + alias.filesz})) {
					return refuse(pc, "frame-alias", "image data has another file-page mapping")
				}
			}
		}
	}
	return nil
}
