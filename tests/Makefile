BINDIR=../bin
SEALDIR=../SEAL

CXX=g++
CXXFLAGS=-march=native -std=c++11 
INCLUDES=$(addprefix -I,$(SEALDIR))
LIB=$(addprefix -L,$(BINDIR)) -lseal

all: clean compile exec

compile: demoNegatif.cpp
	$(CXX) $^ $(CXXFLAGS) $(INCLUDES) $(LIB) -o demoNegatif

exec:
	@./demoNegatif

clean:
	@clear
	@find . -name "demoNegatif" -delete
