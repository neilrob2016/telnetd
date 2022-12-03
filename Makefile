UNAME := $(shell uname -s)
ifeq ($(UNAME),Linux)
	CLIB=-lcrypt
endif

CC=cc  

# If you're feeling brave you can try and compile it on ARM Linux
#CC=aarch64-poky-linux-gcc --sysroot=/opt/fsl-imx-wayland/4.19-warrior/sysroots/aarch64-poky-linux

ARGS=-g -Wall -pedantic
OBJS= \
	main.o \
	config.o \
	master.o \
	slave.o \
	telopt.o \
	network.o \
	validate.o \
	printf.o \
	pty.o \
	split.o \
	misc.o
BIN=telnetd
BIN2=tduser

$(BIN): build_date $(OBJS) Makefile $(BIN2)
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

network.o: network.c globals.h
	$(CC) $(ARGS) -c network.c

validate.o: validate.c globals.h
	$(CC) $(ARGS) -c validate.c

pty.o: pty.c globals.h
	$(CC) $(ARGS) -c pty.c

split.o: split.c globals.h
	$(CC) $(ARGS) -c split.c

misc.o: misc.c globals.h
	$(CC) $(ARGS) -c misc.c

$(BIN2): tduser.c build_date
	$(CC) $(ARGS) tduser.c $(CLIB) -o $(BIN2)

build_date:
	echo "#define BUILD_DATE \"`date -u +'%F %T %Z'`\"" > build_date.h

clean:
	rm -r -f $(BIN) $(OBJS) $(BIN2) *dSYM build_date.h 
