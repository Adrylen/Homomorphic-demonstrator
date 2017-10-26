BINDIR=../bin
SEALDIR=../SEAL

CXX=g++
CXXFLAGS=-march=native -O3 -std=c++11
INCLUDES=$(addprefix -I,$(SEALDIR))
LIB=$(addprefix -L,$(BINDIR)) -lseal

filter: filter.cpp
	$(CXX) $^ $(CXXFLAGS) $(INCLUDES) $(LIB) -lpng -o $@

clean:
	@find . -name "filter" -delete