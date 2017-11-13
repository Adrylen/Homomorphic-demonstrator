#include <fstream>
#include <iostream>
#include <string>
#include <vector>

using namespace std;

void load(istream &stream)
{
	int32_t unb, deuxb, troisb;

	stream.read(reinterpret_cast<char*>(&unb), sizeof(int32_t));
	stream.read(reinterpret_cast<char*>(&deuxb), sizeof(int32_t));
	stream.read(reinterpret_cast<char*>(&troisb), sizeof(int32_t));

	printf("%d %d %d\n", unb, deuxb, troisb);
}

void save(ostream &stream)
{
	int un = 1, deux = 2, trois = 3;

	stream.write(reinterpret_cast<const char*>(&un), sizeof(int32_t));
	stream.write(reinterpret_cast<const char*>(&deux), sizeof(int32_t));
	stream.write(reinterpret_cast<const char*>(&trois), sizeof(int32_t));
}

int main(int argc, char* argv[])
{
	

	ofstream file;

	file.open("IOStream", ios::out | ios::app | ios::binary);

	save(file);

	file.close();

	

	ifstream file2;

	file2.open("IOStream", ios::in | ios::binary);

	load(file2);

	file2.close();

	
}

