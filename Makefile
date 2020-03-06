BUILD_DIR = $(CURDIR)/build
LOCAL_DIR = $(CURDIR)
DEBUG_FLAGS = -DCMAKE_BUILD_TYPE=Debug
REL_FLAGS = -DCMAKE_BUILD_TYPE=RelWithDebInfo

ifneq ($(INSTALL_PREFIX),)
DEBUG_FLAGS += -DCMAKE_INSTALL_PREFIX=$(INSTALL_PREFIX)
REL_FLAGS += -DCMAKE_INSTALL_PREFIX=$(INSTALL_PREFIX)
endif

all: _make_build_dir _compile_rel

PHONY: all _make_build_dir _compile_debug _compile_rel _install \
	   build_release build_debug install

_make_build_dir:
	mkdir -p $(BUILD_DIR)

_compile_debug:
	cd $(BUILD_DIR) && cmake $(LOCAL_DIR) $(DEBUG_FLAGS) && make

_compile_rel:
	cd $(BUILD_DIR) && cmake $(LOCAL_DIR) $(REL_FLAGS) && make

_package:
	cd $(BUILD_DIR) && cpack
_clean:
	rm -rf $(BUILD_DIR)
	
# Release Version, No Debug Symbol and Optimized with -O2
release: _make_build_dir _compile_rel
# Debug Version, Optimized with -O0
debug: _make_build_dir _compile_debug
# Package
package: _package
# Clean
clean: _clean
