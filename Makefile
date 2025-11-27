vuln-app: vuln-app.c
	$(CC) $(CFLAGS) vuln-app.c -o vuln-app

clean:
	rm -f vuln-app