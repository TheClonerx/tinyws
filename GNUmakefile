
CPPFLAGS+= -Iinclude
sources=src/tinyws.c

all: libtinyws.a

include $(sources:.c=.d)

%.d: %.c
	@set -e; rm -f $@; \
	$(CC) -M $(CPPFLAGS) $< > $@.$$$$; \
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	 rm -f $@.$$$$

src/tinyws.o src/tinyws.d: src/tinyws.c include/tinyws.h

libtinyws.a(src/tinyws.o): src/tinyws.o
	ar cr $@ $^

libtinyws.a: libtinyws.a(src/tinyws.o)
	ranlib libtinyws.a

clean:
	@rm -vf $(sources:.c=.d) $(sources:.c=.o) libtinyws.a

.PHONY: all clean