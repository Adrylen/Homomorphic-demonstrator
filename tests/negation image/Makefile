BINDIR=../../bin
SEALDIR=../../SEAL

CXX=g++
CXXFLAGS=-march=native -std=c++11 
INCLUDES=$(addprefix -I,$(SEALDIR))
LIB=$(addprefix -L,$(BINDIR)) -lseal -lpng

all: clean compile

compile: negationImage.cpp
	$(CXX) $^ $(CXXFLAGS) $(INCLUDES) $(LIB) -o negationImage

exec:
	@./negationImage

clean:
	@clear
	@find . -name "negationImage" -delete
