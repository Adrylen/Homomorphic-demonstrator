BINDIR=../../bin
SEALDIR=../../SEAL

CXX=g++
CXXFLAGS=-march=native -std=c++11 
INCLUDES=$(addprefix -I,$(SEALDIR))
LIB=$(addprefix -L,$(BINDIR)) -lseal -lpng

all: clean compile

compile: testIOBinary.cpp
	$(CXX) $^ $(CXXFLAGS) $(INCLUDES) $(LIB) -o testIOBinary

exec:
	@./testIOBinary

clean:
	@clear
	@find . -name "testIOBinary" -delete
