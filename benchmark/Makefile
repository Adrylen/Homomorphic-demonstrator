BINDIR=../bin
SEALDIR=../SEAL

CXX=g++
CXXFLAGS=-march=native -O3 -std=c++11
INCLUDES=$(addprefix -I,$(SEALDIR))
LIB=$(addprefix -L,$(BINDIR)) -lseal

all: clean compile exec

compile: benchmark.cpp
	$(CXX) $^ $(CXXFLAGS) $(INCLUDES) $(LIB) -o benchmark

exec:
	@./benchmark

clean:
	@clear
	@find . -name "benchmarkResults.txt" -delete
	@find . -name "benchmark" -delete
