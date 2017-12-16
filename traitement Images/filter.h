#include <vector>
#include <string>
#include <iostream>

using namespace std;

#ifndef FILTER_H
#define FILTER_H
class Filter
{
	public :

		Filter(string name, int height, int width, vector<int> values);
		
		void print();
		
		int getValue(int x, int y);
		int getNorm();

		int getHeight()	{ return filterHeight;	}
		int getWidth()	{ return filterWidth;	}
		bool validate() { return (filterHeight%2 == 1) && (filterWidth%2 == 1); }
		

	private :
		string filterName;
		int filterHeight;
		int filterWidth;
		vector<int> filterValues;
};
#endif	//FILTER_H