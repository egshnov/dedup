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

#ccflags-y := $(ccflags-y) -xc -E -v


dedup-y := main.o

obj-m := dedup.o
