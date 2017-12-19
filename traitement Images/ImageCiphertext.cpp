#include "image.h"

ImageCiphertext::ImageCiphertext(ImageCiphertext& autre)
{
	this->imageParameters = autre.imageParameters;
	this->pKey = autre.pKey;
	this->gKey = autre.gKey;
	this->imageWidth = autre.imageWidth;
	this->imageHeight = autre.imageHeight;
	this->normalisation = autre.normalisation;
	this->encryptedImageData = autre.encryptedImageData;
}

ImageCiphertext& ImageCiphertext::operator=(const ImageCiphertext& assign)
{
	this->imageParameters = assign.imageParameters;
	this->imageHeight = assign.imageHeight;
	this->imageWidth = assign.imageWidth;
	this->normalisation = assign.normalisation;
	this->pKey = assign.pKey;
	this->gKey = assign.gKey;
	this->encryptedImageData = assign.encryptedImageData;
}


ImageCiphertext::ImageCiphertext(EncryptionParameters parameters, int height, int width, PublicKey pKey, GaloisKeys gKey, vector<Ciphertext> encryptedData)
{
	this->imageParameters = parameters;
	this->imageHeight = height;
	this->imageWidth = width;
	this->pKey = pKey;
	this->gKey = gKey;
	this->encryptedImageData = encryptedData;

	initNorm();
}

void ImageCiphertext::negate()
{
	if(verifyNormOver(1.0))
	{
		SEALContext imageContext(imageParameters);

		Evaluator evaluator(imageContext);

		cout << "beggining negate" << endl;

		auto timeStart = chrono::high_resolution_clock::now();

		for(uint64_t i = 0; i < encryptedImageData.size(); i++)
		{
			//works as it is because values of pixels are centered inside plain modulus, so zero will end up to be 255 (after offset is removed), and vice-versa
			evaluator.negate(encryptedImageData.at(i));
		}

		auto timeStop = chrono::high_resolution_clock::now();

		cout << "--> end of negate: " << chrono::duration_cast<chrono::milliseconds>(timeStop - timeStart).count() << " milliseconds" << endl << endl;
	}
	else
	{
		cout << "can't negate, normalisation necessary" << endl;
	}
	
}

void ImageCiphertext::grey()
{
	SEALContext imageContext(imageParameters);
	Evaluator evaluator(imageContext);
	PolyCRTBuilder crtbuilder(imageContext);

	//calculating offset value
	uint64_t plainModulus = *imageContext.plain_modulus().pointer();
	int offset = (int)(plainModulus - 255) / 2;

	if(offset < 25500)
	{
		cout << "offset too low, increase plainModulus";
		return;
	}

	//the values contained here are the percentage values of each color to be taken to make the grey
	//those are multiplied by 100 to be integers, and have to be normalised afterward
	//this is done automaticaly with the help of the normalisation matrix
	vector<uint64_t> redCoeff(crtbuilder.slot_count(), 21);
	vector<uint64_t> greenCoeff(crtbuilder.slot_count(), 72);
	vector<uint64_t> blueCoeff(crtbuilder.slot_count(), 7);
	vector<uint64_t> offsetVec(crtbuilder.slot_count(), offset);

	Plaintext redCoeffCRT, greenCoeffCRT, blueCoeffCRT, offsetPlain;
	Ciphertext weightedRed, weightedGreen, weightedBlue, tampon;

	crtbuilder.compose(redCoeff, redCoeffCRT);
	crtbuilder.compose(greenCoeff, greenCoeffCRT);
	crtbuilder.compose(blueCoeff, blueCoeffCRT);
	crtbuilder.compose(offsetVec, offsetPlain);

	cout << "beggining greying" << endl;

	auto timeStart = chrono::high_resolution_clock::now();

	for(uint64_t i = 0; i < encryptedImageData.size(); i += 3)
	{
		//removing offset to multiply only pixel value
		evaluator.sub_plain(encryptedImageData.at(i), offsetPlain, tampon);
		evaluator.multiply_plain(tampon, redCoeffCRT, weightedRed);

		evaluator.sub_plain(encryptedImageData.at(i+1), offsetPlain, tampon);
		evaluator.multiply_plain(tampon, greenCoeffCRT, weightedGreen);

		evaluator.sub_plain(encryptedImageData.at(i+2), offsetPlain, tampon);
		evaluator.multiply_plain(tampon, blueCoeffCRT, weightedBlue);


		//adding every value to one ciphertext, then putting back offset
		evaluator.add(weightedRed, weightedGreen);
		evaluator.add(weightedRed, weightedBlue);
		evaluator.add_plain(weightedRed, offsetPlain);

		//replacing old values to new ones
		encryptedImageData.at(i) = weightedRed;
		encryptedImageData.at(i+1) = weightedRed;
		encryptedImageData.at(i+2) = weightedRed;
	}

	//every value was multiplied by 100, so multiplying values by 0.01 at decoding is necessary
	updateNorm(0.01);

	auto timeStop = chrono::high_resolution_clock::now();

	cout << "--> end of greying: " << chrono::duration_cast<chrono::milliseconds>(timeStop - timeStart).count() << " milliseconds" << endl << endl;
}


void ImageCiphertext::applyFilter(Filter filter, int numThreads)
{
	if(filter.validate())
	{
		SEALContext imageContext(imageParameters);
		PolyCRTBuilder crtbuilder(imageContext);
		Evaluator evaluator(imageContext);
		vector<Ciphertext> newEncryptedData(imageHeight*3, Ciphertext());
		string progressBar = string(21*numThreads, ' ');

		//internal function to call for each thread
		auto calculatePart = [&crtbuilder, &evaluator, &newEncryptedData, &progressBar, this](int threadIndex, Filter filter, mutex &rmtx, mutex &wmtx, int xBegin, int xEnd, const MemoryPoolHandle &pool)
		{
			SEALContext imageContext(imageParameters);
			vector<Ciphertext> pixelResults;
			Ciphertext tampon(pool);

			int instantProgress = 0;
			int progressPercentage = -1;

			while(!wmtx.try_lock());
			cout << "thread n°" << threadIndex << " beginning calculations from line " << xBegin << " to line " << xEnd << endl;
			wmtx.unlock();

			for(int x = xBegin; x <= xEnd; x++)	//works on each assigned line of the picture
			{
				for(int colorLayer = 0; colorLayer < 3; colorLayer++) //works on each color layer
				{
					pixelResults.clear();

					for(int y = 0; y < imageWidth; y++)	//works on each pixel of the current line
					{
						//calculation of the new value of the pixel at (x,y) on layer colorLayer
						pixelResults.push_back(convolute(imageContext, x, y, colorLayer, filter, ref(rmtx), pool));

						//progress bar printing part
						instantProgress++;
						int currentProgressPercentage = (int)(((float)instantProgress/(imageWidth*(xEnd-xBegin+1)*3))*100);
						if(currentProgressPercentage != progressPercentage)
						{
							progressPercentage = currentProgressPercentage;

							string insert = "thread n°";
							insert.append(to_string(threadIndex));
							insert.append(" [ ");
							insert.append(to_string(progressPercentage));
							insert.append("% ] ");

							while(!wmtx.try_lock());
							progressBar.replace((threadIndex-1)*21, insert.length(), insert);
							cout << "\r" << progressBar;
							cout.flush();
							wmtx.unlock();
						}
					}
					evaluator.add_many(pixelResults, tampon);

					if(filter.getNorm() == 0)	//additionnal pixel normalisation if sum of factors in filter is zero (plain pixels normalisation process)
					{
						vector<uint64_t> additionnalOffset(crtbuilder.slot_count(), 128);
						Plaintext addOffsetPlain;
						crtbuilder.compose(additionnalOffset, addOffsetPlain);
						evaluator.add_plain(tampon, addOffsetPlain);
					}
					else if(filter.getNorm() < 0)	//additionnal pixel normalisation if sum of factors in filters is less than zero (plain pixels normalisation process)
					{
						vector<uint64_t> additionnalOffset(crtbuilder.slot_count(), 255);
						Plaintext addOffsetPlain;
						crtbuilder.compose(additionnalOffset, addOffsetPlain);
						evaluator.add_plain(tampon, addOffsetPlain);
					}

					while(!wmtx.try_lock());	
					newEncryptedData[x*3+colorLayer] = tampon;	//writing new encrypted line to global array of data
					wmtx.unlock();
				}
			}
		};
		
		mutex readMutex, writeMutex;	//mutex to synchronize prints to stdout between threads, and reads from data 
		vector<thread> threads;

		cout << "applying filter :" << endl;
		filter.print();

		unsigned int numThreadsAdvised = thread::hardware_concurrency();	//checking number of available threads
		cout << "possible number of threads : " << numThreadsAdvised << endl;
		if(numThreads > numThreadsAdvised && numThreadsAdvised != 0)
		{
			cout << "number of threads asked for is too high, getting down to " << numThreadsAdvised << " threads" << endl;
			numThreads = numThreadsAdvised;
		}

		if(numThreads > imageHeight)
		{
			cout << "too much threads for the height of the image, getting down to " << imageHeight << " threads" << endl;
			numThreads = imageHeight;
		}

		vector<int> linesPerThread(numThreads, 0);

		for(int i = 0; i < imageHeight; i++)	//assigning a number of lines to process for each thread (quite simple method)
		{
			linesPerThread[i%numThreads]++;
		}

		auto timeStart = chrono::high_resolution_clock::now();

		int sum = 0;
		for(int i = 0; i < numThreads; i++)
		{
			//launching each thread 
			threads.emplace_back(calculatePart, i+1, filter, ref(readMutex), ref(writeMutex), sum, (sum)+linesPerThread[i]-1, MemoryPoolHandle::New(false));
			sum += linesPerThread[i];
		}
		
		for(int j = 0; j < threads.size(); j++)
		{
			//waiting for each thread to finish 
			threads[j].join();
		}

		//replacing old array of data to new one
		encryptedImageData.clear();
		encryptedImageData = newEncryptedData;

		auto timeStop = chrono::high_resolution_clock::now();

		cout << "\nfiltering finished: " << chrono::duration_cast<chrono::seconds>(timeStop - timeStart).count() << " seconds" << endl << endl;
	}
}

void ImageCiphertext::save(string fileName)
{

	cout << "saving crypted file '" << fileName << "'" << endl << endl;

	ofstream fileBin;
	fileBin.open(fileName, ios::out | ios::binary);

	imageParameters.save(fileBin);
	pKey.save(fileBin);

	for(uint64_t i=0; i<encryptedImageData.size(); i++)
	{
		encryptedImageData.at(i).save(fileBin);
	}
	fileBin.close();
}

void ImageCiphertext::load(string fileName)
{
	cout << "loading crypted file '" << fileName << "'" << endl << endl;

	ifstream fileBin;
	fileBin.open(fileName, ios::in | ios::binary);

	imageParameters.load(fileBin);
	pKey.load(fileBin);

	for(uint64_t i=0; i<encryptedImageData.size(); i++)
	{
		encryptedImageData.at(i).load(fileBin);
	}
	fileBin.close();
}


void ImageCiphertext::printParameters()
{
	SEALContext imageContext(imageParameters);
    cout << endl << "/ Encryption parameters:" << endl;
    cout << "| poly_modulus: " << imageContext.poly_modulus().to_string() << endl;

    /*
    Print the size of the true (product) coefficient modulus
    */
    cout << "| coeff_modulus size: " 
        << imageContext.total_coeff_modulus().significant_bit_count() << " bits" << endl;

    cout << "| plain_modulus: " << imageContext.plain_modulus().value() << endl;
    cout << "\\ noise_standard_deviation: " << imageContext.noise_standard_deviation() << endl;
    cout << "/ image height: " << imageHeight << endl;
    cout << "| image width: " << imageWidth << endl;
    cout << "\\ offset applied to values: " << (int)(imageContext.plain_modulus().value() - 255) / 2 << endl;

    cout << endl;
}


//###########################################################################################################
//####################################### private classes ###################################################
//###########################################################################################################

Ciphertext ImageCiphertext::addColumns(SEALContext context, Ciphertext cipher, int position, int min, int max, const MemoryPoolHandle &pool)
{
	// cout << "		addRows from " << min << " to " << max << " on position " << position << endl;	//DEBUG
    Evaluator evaluator(context);
    PolyCRTBuilder crtbuilder(context);

    vector<uint64_t> selector(crtbuilder.slot_count(), 0);
    Ciphertext tampon(pool);
    Plaintext selectorPlain(pool);

    int polyLength = context.poly_modulus().significant_coeff_count() - 1;

    for(int coeff = min; coeff <= max; coeff++)
    {
        if(coeff == position) continue;		//prevent pixel that has to take new value to be added with itself

        //selecting coefficient
        selector[coeff] = 1;
        crtbuilder.compose(selector, selectorPlain);
        evaluator.multiply_plain(cipher, selectorPlain, tampon, pool);	//tampon olds all zeros except for the pixel selected at index 'coeff'

        //shifting the value of the pixel to the position 'position'
        //second argument is number of shifts, positive is rotating left, negative shifts right
        evaluator.rotate_rows(tampon, (coeff-position), gKey, pool);    

        //rotation works on ciphertext represented as a 2 by (polyLength/2), so if the position is in first line 
        //and the pixel to move is in second line (example : pos = 511 and pixel = 513, with polyLength = 1024), program also has to 
        //rotate the lines for the pixel to be in the good one (see SEAL documentation)
        if(((position < polyLength/2) && (coeff >= polyLength/2)) || ((position >= polyLength/2) && (coeff < polyLength/2)))
        {
        	evaluator.rotate_columns(tampon, gKey, pool);
        }

        //adding new cipher with original one, now the value at position is the old one added with the value at coeff
        evaluator.add(cipher, tampon);

        selector[coeff] = 0;
    }

    return cipher;
}


Ciphertext ImageCiphertext::convolute(SEALContext context, int x, int y, int colorLayer, Filter filter, mutex &rmtx, const MemoryPoolHandle &pool)
{
	int sum = 0;

	Evaluator evaluator(context);
	PolyCRTBuilder crtbuilder(context);

	Plaintext multiplierPlain(pool);
	vector<Ciphertext> tampons;

	int verticalOffset = (int) filter.getHeight()/2;
	int horizontalOffset = (int) filter.getWidth()/2;

	//preparing offset value to process multiplications
	uint64_t plainModulus = *context.plain_modulus().pointer();
	int offsetVal = (int)(plainModulus - 255) / 2;

	vector<uint64_t> offsetVec(crtbuilder.slot_count(), offsetVal);
	Plaintext offset(pool);
	crtbuilder.compose(offsetVec, offset);

	for(int xOffset = -verticalOffset; xOffset <= verticalOffset; xOffset++)		//working on each line of the filter
	{
		vector<Ciphertext> pixelsLine;
		Ciphertext line(context.parms(), pool), data(context.parms(), pool);
		int currentX;

		((x + xOffset) < 0) ? (currentX = 0) : (((x+xOffset) > imageHeight - 1) ? (currentX = imageHeight - 1) : (currentX = x + xOffset));

		while(!rmtx.try_lock());
		data = encryptedImageData[(currentX)*3 + colorLayer];
		rmtx.unlock();

		for(int yOffset = -horizontalOffset; yOffset <= horizontalOffset; yOffset++)	//working on each value of the line of the filter
		{
			vector<uint64_t> multiplier(crtbuilder.slot_count(), 0);
			int currentY;
			Ciphertext tampon(data);

			((y + yOffset) < 0) ? (currentY = 0) : (((y+yOffset) > imageWidth - 1) ? (currentY = imageWidth - 1) : (currentY = y + yOffset));

			//getting value of filter at relative position
			int mult = filter.getValue(verticalOffset + xOffset, horizontalOffset + yOffset);

			sum += mult;

			//making sure the multiplier selector contains only positive values (negation is taken care of after)
			(mult < 0) ? (multiplier[currentY] = -mult) : (multiplier[currentY] = mult);

			crtbuilder.compose(multiplier, multiplierPlain);
			if(mult != 0)
			{
				//offset removed to process multiplication (don't want to multiply the offset)
				evaluator.sub_plain(tampon, offset);	

				if(mult < 0)
				{
					//negating value in case filter value at position is negative
					//(every value of the cipher is negated, but we only use the one at current position)
					evaluator.negate(tampon);	
				}

				//multiplying values of ciphertext with the value in filter
				//to successfuly change the pixel value at corresponding position and deleting every other value
				evaluator.multiply_plain(tampon, multiplierPlain, pool);

				//adding every ciphertext to a list of vectors
				pixelsLine.push_back(tampon);
			}
			
		}
		//adding each ciphertext to one, to put every value in different positions and different ciphertexts into only one ciphertext
		//thus, the line ciphertext contains X contiguous values (X being the dimmension of the filtering matrix)
		evaluator.add_many(pixelsLine, line);

		tampons.push_back(line);
	}

	Ciphertext partialResult(pool), result(pool);
	//adding every ciphertext containing X non-null values into one, to add pixel values multiplied in only one line
	//the resulting ciphertext has the result of the convolution operation in the sum of it's values (X values, rest is null)
	evaluator.add_many(tampons, partialResult);	

	int YBegin, YEnd;
	(y < horizontalOffset) ? (YBegin = -y) : (YBegin = -horizontalOffset);
	(y < (imageWidth - horizontalOffset)) ? (YEnd = horizontalOffset) : (YEnd = (imageWidth - 1 - y));

	//finally, adds every value in the partialResult ciphertext in a single position, 
	//corresponding to the resulting value of pixel at position y in line x
	result = addColumns(context, partialResult, y, y+YBegin, y+YEnd, pool);	

	evaluator.add_plain(result, offset);	//setting back the offset before deleting every value except the one on position y

	vector<uint64_t> selectorNew(crtbuilder.slot_count(), 0);	
	selectorNew[y] = 1;	
	crtbuilder.compose(selectorNew, multiplierPlain);
	//multiplying the result with a vector with value 1 at position y, zero everywhere else, to keep only the result of convolution on position y
	evaluator.multiply_plain(result, multiplierPlain, pool);	

	if(sum != 0)
	{
		if(sum < 0)	sum = -sum;
		while(!rmtx.try_lock());
		normalisation[x][y][colorLayer] *= (float)1/sum;	//modifying normalisation for this pixel 
		rmtx.unlock();
	}

	return result;
}

void ImageCiphertext::initNorm()
{
	normalisation = (float***) malloc(imageHeight*sizeof(*normalisation));

	for(int i = 0; i < imageHeight; i++)
	{
		normalisation[i] = (float**) malloc(imageWidth*sizeof(**normalisation));

		for(int j = 0; j < imageWidth; j++)
		{
			normalisation[i][j] = (float*) malloc(3*sizeof(***normalisation));
		}
	}


	for(int i = 0; i < imageHeight; i++)
	{
		for(int j = 0; j < imageWidth; j++)
		{
			for(int k = 0; k < 3; k++)
			{
				normalisation[i][j][k] = 1.0;		
			}
		}
	}
}

void ImageCiphertext::updateNorm(float value)
{
	for(int i = 0; i < imageHeight; i++)
	{
		for(int j = 0; j < imageWidth; j++)
		{
			for(int k = 0; k < 3; k++)
			{
				normalisation[i][j][k] *= value;
			}
		}
	}
}

bool ImageCiphertext::verifyNormOver(float value)
{
	bool result = true;

	for(int i =0; i < imageHeight; i++)
	{
		for(int j = 0; j > imageWidth; j++)
		{
			for(int k = 0; k < 3; k++)
			{
				if(normalisation[i][j][k] < value)
				{
					result = false;
				}
			}
		}
	}

	return result;
}
