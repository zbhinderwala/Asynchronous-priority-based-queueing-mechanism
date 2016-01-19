obj-m += submitjob_mod.o

submitjob_mod-objs := sys_submitjob.o encrypt_decrypt.o checksum.o concat.o compress_decompress.o

INC=/lib/modules/$(shell uname -r)/build/arch/x86/include

all: produce_job submitjob

nlink.o:
	gcc -c -Wall -Werror nlink.c -o nlink.o
produce_job: produce_job.c nlink.o
	gcc -Wall -Werror -I$(INC)/generated/uapi -I$(INC)/uapi produce_job.c nlink.o -o produce_job -lcrypto -lssl -lpthread

submitjob:
	make -Wall -Werror -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f produce_job
