ccflags-y := 	-Wall					\
		-Wextra					\
		-Wno-missing-field-initializers		\
		-Wno-unused-parameter			\
		-Wformat				\
		-O2					\
		-std=gnu18				\
		-g					\
		-Werror=format-security			\
		-Werror=implicit-function-declaration	


dedup-y := main.o index/memtable.o index/pbn_manager.o

obj-m := dedup.o
