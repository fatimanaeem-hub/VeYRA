# VEYRA Veins project. Run ./configure once, then make.
all: checkmakefiles
	@cd src && $(MAKE)

clean: checkmakefiles
	@cd src && $(MAKE) clean

cleanall:
	@test -f src/Makefile && (cd src && $(MAKE) MODE=release clean; $(MAKE) MODE=debug clean) || true
	@rm -f src/Makefile out/veins_path

checkmakefiles:
	@if [ ! -f src/Makefile ]; then \
	echo; echo '=================================================='; \
	echo 'src/Makefile does not exist. Run ./configure first.'; \
	echo '=================================================='; echo; exit 1; fi

.PHONY: all clean cleanall checkmakefiles
