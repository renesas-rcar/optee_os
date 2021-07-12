# Input
#
# libname	tells the name of the lib and
# libdir	tells directory of lib which also is used as input to
#		mk/subdir.mk
# conf-file     [optional] if set, all objects will depend on $(conf-file)
#
# Output
#
# updated cleanfiles and
# updated libfiles, libdirs, libnames and libdeps

lib-libfile	 = $(out-dir)/$(base-prefix)$(libdir)/lib$(libname).a
cleanfiles	:= $(cleanfiles) $(lib-libfile)
libfiles	:= $(lib-libfile) $(libfiles)
libdirs 	:= $(out-dir)/$(base-prefix)$(libdir) $(libdirs)
libnames	:= $(libname) $(libnames)
libdeps		:= $(lib-libfile) $(libdeps)

define process-lib
$(lib-libfile): $(objs)
	@echo '  CP      $$@'
	@mkdir -p $$(dir $$@)
	@cp -Rp $(libdir)/lib$(libname).a $(out-dir)/$(base-prefix)$(libdir)
endef #process-lib

$(eval $(call process-lib))

$(objs): $(conf-file)

# Clean residues from processing
objs		:=
libname		:=
lib-use-ld	:=
sansa-library :=
