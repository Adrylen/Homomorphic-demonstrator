#include <vector>
#include <string>
#include <iostream>

using namespace std;

#ifndef FILTER_H
#define FILTER_H
class Filter
{
	public :

	Filter(int height, int width, vector<int> values)
	{
		filterHeight = height;
		filterWidth = width;
		filterValues = values;
	}


	void print()
	{
		for(int i=0; i<filterHeight; i++)
		{
			for(int j=0; j<filterWidth; j++)
			{
				cout << filterValues[i*filterWidth+j] << " ";
			}
			cout << endl;
		}
	}

	int getValue(int x, int y)
	{
		if(x > filterHeight - 1)
			throw invalid_argument("x over height of filter matrix");
		if(y > filterWidth - 1)
			throw invalid_argument("y over width of filter matrix");

		return filterValues[x*filterWidth+y];
	}

	int getHeight()
	{
		return filterHeight;
	}

	int getWidth()
	{
		return filterWidth;
	}

	float getNorm()
	{
		int sum = 0;

		for(int i=0; i<filterValues.size(); i++)
		{
			sum += filterValues[i];
		}

		return (float) 1/sum;
	}

	bool validate()
	{
		return (filterHeight%2 == 1) && (filterWidth%2 == 1);
	}
	

	private :
		int filterHeight;
		int filterWidth;
		vector<int> filterValues;
};
#endif	//FILTER_H