QASAN_BIN := ~/Desktop/QASAN/qemu/i386-softmmu/qemu-system-i386

all: run

run: build
	$(QASAN_BIN) -kernel baremetal_x86_1.bin

build: boot utils terminal malloc main
	gcc -m32 -T linker.ld -o baremetal_x86_1.bin -ffreestanding -nostdlib boot.o utils.o terminal.o malloc.o main.o

boot:
	gcc -m32 -c boot.s -o boot.o

main:
	gcc -m32 -c main.c -o main.o -std=gnu99 -ffreestanding -Wall -Wextra

utils:
	gcc -m32 -c utils.c -o utils.o -std=gnu99 -ffreestanding -Wall -Wextra

malloc:
	gcc -m32 -c malloc.c -o malloc.o -std=gnu99 -ffreestanding -Wall -Wextra

terminal:
	gcc -m32 -c terminal.c -o terminal.o -std=gnu99 -ffreestanding -Wall -Wextra

clean:
	rm *.o *.bin
