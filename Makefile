all:
	mkdir -p bin
	g++ -o ./bin/main ./src/main.cpp
	sudo ./bin/main