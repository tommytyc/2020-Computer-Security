dns_attack: main.o dnsamp.o
	gcc -o dns_attack main.o dnsamp.o

main.o: main.c
	gcc -c main.c

dnsamp.o: dnsamp.c dnsamp.h
	gcc -c dnsamp.c dnsamp.h

clean:
	rm -f *.o *.h.gch dns_attack