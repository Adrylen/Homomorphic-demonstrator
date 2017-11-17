BINDIR=../bin
SEALDIR=../SEAL

CXX=g++
CXXFLAGS=-march=native -std=c++11 
INCLUDES=$(addprefix -I,$(SEALDIR))
LIB=$(addprefix -L,$(BINDIR)) -lseal -lpng

all: clean compile

compile: main.cpp
	$(CXX) $^ $(CXXFLAGS) $(INCLUDES) $(LIB) -o traitementImage

exec:
	@./traitementImage

clean:
	@clear
	@find . -name "traitementImage" -delete
