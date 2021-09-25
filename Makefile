# Linux only. Comment out for MacOS
CLIB=-lcrypt

CC=cc 

# For 950 router build
#CC=aarch64-poky-linux-gcc --sysroot=/opt/fsl-imx-wayland/4.19-warrior/sysroots/aarch64-poky-linux

ARGS=-g -Wall -pedantic
OBJS=main.o master_child.o slave_child.o telopt.o io.o printf.o pty.o
BIN=telnetd

$(BIN): build_date $(OBJS) Makefile
	$(CC) $(OBJS) $(CLIB) -o $(BIN)

main.o: main.c globals.h build_date.h
	$(CC) $(ARGS) -c main.c

master_child.o: master_child.c globals.h
	$(CC) $(ARGS) -c master_child.c

slave_child.o: slave_child.c globals.h
	$(CC) $(ARGS) -c slave_child.c

telopt.o: telopt.c globals.h
	$(CC) $(ARGS) -c telopt.c

printf.o: printf.c globals.h
	$(CC) $(ARGS) -c printf.c

io.o: io.c globals.h
	$(CC) $(ARGS) -c io.c

pty.o: pty.c globals.h
	$(CC) $(ARGS) -c pty.c

build_date:
	echo "#define SVR_BUILD_DATE \"`date -u +'%F %T %Z'`\"" > build_date.h

clean:
	rm -f $(BIN) $(OBJS) build_date.h 
