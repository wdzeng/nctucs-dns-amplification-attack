all:
	mkdir -p bin
	g++ -o ./bin/main ./main.cpp
	sudo ./bin/main