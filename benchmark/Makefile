BINDIR=../bin
SEALDIR=../SEAL

CXX=g++
CXXFLAGS=-march=native -O3 -std=c++11
INCLUDES=$(addprefix -I,$(SEALDIR))
LIB=$(addprefix -L,$(BINDIR)) -lseal

all: clean compile exec

compile: main.cpp
	$(CXX) $^ $(CXXFLAGS) $(INCLUDES) $(LIB) -o main

exec:
	@./main

clean:
	@clear
	@find . -name "benchmark.txt" -delete
	@find . -name "main" -delete
