# default compiler flags
CFLAGS ?= -std=c11 -Wall -Wextra -pedantic
# if the env var ADMIN_AES_KEY exists, its value is compiled into the executable
# if not, it becomes empty string
CFLAGS += $(if $(ADMIN_AES_KEY),-DADMIN_AES_KEY=\"$(ADMIN_AES_KEY)\",-DADMIN_AES_KEY=\"\")

# placeholder in case of override from command line
LDFLAGS ?=
# include openSSL cryptography library 
LDLIBS ?= -lcrypto

#declare build targer, restrict file permissions so only owner can read/write/exec
vuln-app: vuln-app.c 
	$(CC) $(CFLAGS) vuln-app.c $(LDFLAGS) $(LDLIBS) -o vuln-app
	chmod 700 vuln-app

clean:
	rm -f vuln-app