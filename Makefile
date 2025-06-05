# RetroSSL Makefile for Windows 98 SE using Open Watcom
WATCOM_ROOT = opt
export WATCOM = $(shell pwd)/$(WATCOM_ROOT)
export PATH := $(WATCOM_ROOT)/armo64:$(PATH)

CC = wcl386
CFLAGS = -bt=nt -i$(WATCOM_ROOT)/h -i$(WATCOM_ROOT)/h/nt -zq -w4 -ox -dWIN32 -d_WIN32

# Test programs  
basic_test.exe: basic_test.c
	$(CC) $(CFLAGS) -fe=$@ $<

simple_test.exe: simple_test.obj
	$(LINK) $(LDFLAGS) file simple_test.obj name simple_test.exe

simple_test.obj: simple_test.c
	$(CC) $(CFLAGS) simple_test.c

test_win98.exe: test_win98.obj
	$(LINK) $(LDFLAGS) file test_win98.obj name test_win98.exe

test_win98.obj: test_win98.c
	$(CC) $(CFLAGS) test_win98.c

clean:
	rm -f *.obj *.exe *.err

.PHONY: clean