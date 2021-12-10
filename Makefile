UNAME := $(shell uname -s)
ifeq ($(UNAME),Linux)
	CLIB=-lcrypt
endif

CC=cc 

# ARM Linux
#CC=aarch64-poky-linux-gcc --sysroot=/opt/fsl-imx-wayland/4.19-warrior/sysroots/aarch64-poky-linux

ARGS=-g -Wall -pedantic
OBJS= \
	main.o \
	config.o \
	master.o \
	slave.o \
	telopt.o \
	io.o \
	printf.o \
	pty.o \
	split.o \
	misc.o
BIN=telnetd

$(BIN): build_date $(OBJS) Makefile
	$(CC) $(OBJS) $(CLIB) -o $(BIN)

main.o: main.c globals.h build_date.h
	$(CC) $(ARGS) -c main.c

config.o: config.c globals.h 
	$(CC) $(ARGS) -c config.c

master.o: master.c globals.h
	$(CC) $(ARGS) -c master.c

slave.o: slave.c globals.h
	$(CC) $(ARGS) -c slave.c

telopt.o: telopt.c globals.h
	$(CC) $(ARGS) -c telopt.c

printf.o: printf.c globals.h
	$(CC) $(ARGS) -c printf.c

io.o: io.c globals.h
	$(CC) $(ARGS) -c io.c

pty.o: pty.c globals.h
	$(CC) $(ARGS) -c pty.c

split.o: split.c globals.h
	$(CC) $(ARGS) -c split.c

misc.o: misc.c globals.h
	$(CC) $(ARGS) -c misc.c

build_date:
	echo "#define SVR_BUILD_DATE \"`date -u +'%F %T %Z'`\"" > build_date.h

clean:
	rm -f $(BIN) $(OBJS) build_date.h 
