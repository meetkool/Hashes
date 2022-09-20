test: hashes.cpp test.cpp
	g++ -c -w hashes.cpp
	g++ -c test.cpp
	g++ -o test hashes.o test.o
	rm ./{hashes,test}.o
