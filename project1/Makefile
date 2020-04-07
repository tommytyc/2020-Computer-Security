dns_attack: main.o dnsamp.o
	g++ -o dns_attack main.o dnsamp.o

main.o: main.cpp
	g++ -c main.cpp

dnsamp.o: dnsamp.cpp dnsamp.h
	g++ -c dnsamp.cpp dnsamp.h

clean:
	rm -f *.o *.h.gch dns_attack