# https://stackoverflow.com/questions/53136024/makefile-to-compile-all-c-files-without-needing-to-specify-them/53138757
# https://stackoverflow.com/questions/28533059/how-to-use-pkg-config-in-make
# https://stackoverflow.com/questions/52034997/how-to-make-makefile-recompile-when-a-header-file-is-changed
GIT_VERSION := "$(shell git describe --abbrev=7 --always --tags)"
CC					:= c++
CFLAGS			:= -std=c++20 -ggdb3 -Wall -Wfatal-errors -D_FORTIFY_SOURCE=2 `pkg-config libelf --cflags` `pkg-config fuse3 --cflags` -DVERSION=\"$(GIT_VERSION)\"
LDFLAGS			:= -static `pkg-config libelf --libs-only-L` `pkg-config fuse3 --libs-only-L`
LDLIBS			:= `pkg-config libelf --libs-only-l --static` `pkg-config fuse3 --libs-only-l --static`
PRG					:= elfs
SOURCES 		:= $(wildcard *.cc)
OBJECTS 		:= $(patsubst %.cc,%.o,$(SOURCES))
DEPENDS 		:= $(patsubst %.cc,%.d,$(SOURCES))

all: $(PRG)

$(PRG): $(OBJECTS)
	$(CC) $(LDFLAGS) $^ -o $@ $(LDLIBS)

-include $(DEPENDS)

%.o: %.cc Makefile
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

clean:
	rm -fr *.o
	rm -fr $(PRG)
	rm -fr $(DEPENDS)

re: clean all

.PHONY: all clean re
