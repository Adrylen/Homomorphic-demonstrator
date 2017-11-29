BINDIR=../bin
SEALDIR=../SEAL

CXX=g++
SOURCE=ImageCiphertext.cpp
SOURCE+=ImagePlaintext.cpp
SOURCE+=filter.cpp
CXXFLAGS=-march=native -std=c++11 
INCLUDES=$(addprefix -I,$(SEALDIR))
LIB=$(addprefix -L,$(BINDIR)) -lseal -lpng
THREAD=-pthread

all: clean compile

compile: main.cpp
	$(CXX) $(SOURCE) $^ $(CXXFLAGS) $(INCLUDES) $(LIB) $(THREAD) -o traitementImage

exec:
	@./traitementImage

clean:
	@clear
	@find . -name "traitementImage" -delete
