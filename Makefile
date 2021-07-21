all:
	cd src/ && make

clean:
	cd src/ && make clean

re:
	cd src/ && make re

.PHONY: all clean re