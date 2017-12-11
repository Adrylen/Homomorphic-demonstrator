#include "image.h"

ImageCiphertext::ImageCiphertext(ImagePlaintext autre) : imageContext(autre.getContext())
{
	pKey = PublicKey();
	sKey = SecretKey();

	generateKeys();

	imageHeight = autre.getHeight();
	imageWidth = autre.getWidth();

	initNorm();
}

ImageCiphertext::ImageCiphertext(ImageCiphertext& autre) : imageContext(autre.getContext())
{
	pKey = autre.getPublicKey();
	sKey = autre.getSecretKey();
	gKey = autre.getGaloisKeys();

	imageWidth = autre.getWidth();
	imageHeight = autre.getHeight();

	initNorm();

	encryptedImageData.resize(autre.getDataSize(), Ciphertext());
}

bool ImageCiphertext::generateKeys()
{
	cout << "generating keys" << endl;

	KeyGenerator generator(imageContext);
    sKey = generator.secret_key();
    pKey = generator.public_key();
    generator.generate_galois_keys(30, gKey);	//attention, le DBC (premier paramètre) devra être adapté en fonction des opérations

    cout << "keys generated successfully" << endl << endl;
}

bool ImageCiphertext::encrypt(ImagePlaintext autre)
{
	Encryptor encryptor(imageContext, pKey);
	Ciphertext cipherTampon = Ciphertext();

	encryptedImageData.clear();

	cout << "début du cryptage image" << endl;

	auto timeStart = chrono::high_resolution_clock::now();

	for(uint64_t i = 0; i < autre.getDataSize(); i++)
	{
		encryptor.encrypt(autre.getDataAt(i), cipherTampon);
		encryptedImageData.push_back(cipherTampon);
	}

	auto timeStop = chrono::high_resolution_clock::now();

	cout << "--> fin du cryptage: " << chrono::duration_cast<chrono::milliseconds>(timeStop - timeStart).count() << " milliseconds" << endl << endl;
}

ImagePlaintext ImageCiphertext::decrypt()
{
	Decryptor decryptor(imageContext, sKey);
	vector<Plaintext> decryptedData;
	Plaintext plainTampon = Plaintext();

	cout << "début du décryptage image" << endl;

	auto timeStart = chrono::high_resolution_clock::now();

	for(uint64_t i = 0; i < encryptedImageData.size(); i++)
	{
		decryptor.decrypt(encryptedImageData.at(i), plainTampon);
		decryptedData.push_back(plainTampon);
	}

	auto timeStop = chrono::high_resolution_clock::now();

	cout << "--> fin décryptage: " << chrono::duration_cast<chrono::milliseconds>(timeStop - timeStart).count() << " milliseconds" << endl << endl;

	return ImagePlaintext(imageContext, imageHeight, imageWidth, normalisation, decryptedData);
}

bool ImageCiphertext::negate()
{
	if(verifyNormOver(1.0))
	{
		uint64_t plainModulus = *imageContext.plain_modulus().pointer();

		int dynamiqueValeursPlain = 255;

		Evaluator evaluator(imageContext);
		PolyCRTBuilder crtbuilder(imageContext);

		vector<uint64_t> reducteur(crtbuilder.slot_count(), plainModulus-dynamiqueValeursPlain);

		Plaintext reduction;
		crtbuilder.compose(reducteur, reduction);

		cout << "beggining negate" << endl;

		auto timeStart = chrono::high_resolution_clock::now();

		for(uint64_t i = 0; i < encryptedImageData.size(); i++)
		{
			evaluator.negate(encryptedImageData.at(i));
			evaluator.sub_plain(encryptedImageData.at(i), reduction);
		}

		auto timeStop = chrono::high_resolution_clock::now();

		cout << "--> end of negate: " << chrono::duration_cast<chrono::milliseconds>(timeStop - timeStart).count() << " milliseconds" << endl << endl;
	}
	else
	{
		cout << "negation impossible, normalisation necessary" << endl;
	}
	
}

bool ImageCiphertext::grey()
{
	Evaluator evaluator(imageContext);
	PolyCRTBuilder crtbuilder(imageContext);

	vector<uint64_t> redCoeff(crtbuilder.slot_count(), 21);
	vector<uint64_t> greenCoeff(crtbuilder.slot_count(), 72);
	vector<uint64_t> blueCoeff(crtbuilder.slot_count(), 7);

	Plaintext redCoeffCRT, greenCoeffCRT, blueCoeffCRT;
	Ciphertext weightedRed, weightedGreen, weightedBlue;

	crtbuilder.compose(redCoeff, redCoeffCRT);
	crtbuilder.compose(greenCoeff, greenCoeffCRT);
	crtbuilder.compose(blueCoeff, blueCoeffCRT);

	cout << "beggining greying" << endl;

	auto timeStart = chrono::high_resolution_clock::now();

	for(uint64_t i=0; i<encryptedImageData.size(); i+=3)
	{
		evaluator.multiply_plain(encryptedImageData.at(i), redCoeffCRT, weightedRed);
		evaluator.multiply_plain(encryptedImageData.at(i+1), greenCoeffCRT, weightedGreen);
		evaluator.multiply_plain(encryptedImageData.at(i+2), blueCoeffCRT, weightedBlue);
		evaluator.add(weightedRed, weightedGreen);
		evaluator.add(weightedRed, weightedBlue);
		encryptedImageData.at(i) = weightedRed;
		encryptedImageData.at(i+1) = weightedRed;
		encryptedImageData.at(i+2) = weightedRed;
	}

	updateNorm(0.01);

	auto timeStop = chrono::high_resolution_clock::now();

	cout << "--> end of greying: " << chrono::duration_cast<chrono::milliseconds>(timeStop - timeStart).count() << " milliseconds" << endl << endl;
}

bool ImageCiphertext::applyFilter(Filter filter)
{
	if(filter.validate() && getNoiseBudget() > 0)
	{
		int instantProgress = 0;
		int progressPercentage = 0;

		PolyCRTBuilder crtbuilder(imageContext);
		Evaluator evaluator(imageContext);
		vector<Ciphertext> newEncryptedData(imageHeight*3, Ciphertext());
		vector<Ciphertext> pixelResults;

		cout << "applying filter :" << endl;
		filter.print();

		auto timeStart = chrono::high_resolution_clock::now();

		for(int x = 0; x < imageHeight; x++)	//travaille sur chaque ligne de l'image 
		{
			for(int colorLayer = 0; colorLayer < 3; colorLayer++) //travaille sur chaque layer de couleur 
			{
				pixelResults.clear();

				for(int y = 0; y < imageWidth; y++)	//travaille sur chaque pixel de la ligne courante
				{
					pixelResults.push_back(convolute2(x, y, colorLayer, filter));

					instantProgress++;
					int currentProgressPercentage = (int)(((float)instantProgress/(imageWidth*imageHeight*3))*100);
					if(currentProgressPercentage != progressPercentage)
					{
						progressPercentage = currentProgressPercentage;
						cout << "\t[ " << progressPercentage << "% ] \r";
						cout.flush();
					}
				}

				evaluator.add_many(pixelResults, newEncryptedData[x*3+colorLayer]);
			}
		}

		encryptedImageData.clear();
		encryptedImageData = newEncryptedData;

		auto timeStop = chrono::high_resolution_clock::now();

		cout << "--> filtering finished: " << chrono::duration_cast<chrono::seconds>(timeStop - timeStart).count() << " seconds" << endl << endl;
	}
}

bool ImageCiphertext::applyFilterThreaded(Filter filter, int numThread)
{
	if(filter.validate() && getNoiseBudget() > 0)
	{
		PolyCRTBuilder crtbuilder(imageContext);
		Evaluator evaluator(imageContext);
		vector<Ciphertext> newEncryptedData(imageHeight*3, Ciphertext());
		string progressBar = string(20*numThread, ' ');


		auto calculatePart = [&crtbuilder, &evaluator, &newEncryptedData, &progressBar, this](int threadIndex, Filter filter, mutex &rmtx, mutex &wmtx, int xBegin, int xEnd, const MemoryPoolHandle &pool)
		{
			vector<Ciphertext> pixelResults;

			int instantProgress = 0;
			int progressPercentage = -1;

			while(!wmtx.try_lock());
			cout << "thread n°" << threadIndex << " beginning calculations from line " << xBegin << " to line " << xEnd << endl;
			wmtx.unlock();

			for(int x = xBegin; x <= xEnd; x++)	//travaille sur chaque ligne de l'image 
			{
				for(int colorLayer = 0; colorLayer < 3; colorLayer++) //travaille sur chaque layer de couleur 
				{
					pixelResults.clear();

					for(int y = 0; y < imageWidth; y++)	//travaille sur chaque pixel de la ligne courante
					{
						pixelResults.push_back(convolute2Threaded(imageContext, imageHeight, imageWidth, x, y, colorLayer, filter, ref(rmtx), pool));

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

					while(!wmtx.try_lock());
					evaluator.add_many(pixelResults, newEncryptedData[x*3+colorLayer]);
					wmtx.unlock();
				}
			}
		};
		
		mutex readMutex, writeMutex;
		vector<thread> threads;

		int i;
		int xByThread = (int)imageHeight/numThread;

		cout << "applying filter :" << endl;
		filter.print();

		auto timeStart = chrono::high_resolution_clock::now();

		for(i = 0; i < numThread-1; i++)
		{
			threads.emplace_back(calculatePart, i+1, filter, ref(readMutex), ref(writeMutex), i*xByThread, (i+1)*xByThread-1, MemoryPoolHandle::New(false));
		}
		threads.emplace_back(calculatePart, i+1, filter, ref(readMutex), ref(writeMutex), i*xByThread, imageHeight-1, MemoryPoolHandle::New(false));

		for(int j = 0; j < threads.size(); j++)
		{
			threads[j].join();
		}

		encryptedImageData.clear();
		encryptedImageData = newEncryptedData;

		auto timeStop = chrono::high_resolution_clock::now();

		cout << "\nfiltering finished: " << chrono::duration_cast<chrono::seconds>(timeStop - timeStart).count() << " seconds" << endl << endl;

		getNoiseBudget();
	}
}

bool ImageCiphertext::save(string fileName)
{

	cout << "sauvegarde du fichier crypté '" << fileName << "'" << endl << endl;

	ofstream fileBin;
	fileBin.open(fileName, ios::out | ios::binary);

	sKey.save(fileBin);
	pKey.save(fileBin);

	for(uint64_t i=0; i<encryptedImageData.size(); i++)
	{
		encryptedImageData.at(i).save(fileBin);
	}
	fileBin.close();
}

bool ImageCiphertext::load(string fileName)
{
	cout << "chargement du fichier crypté '" << fileName << "'" << endl << endl;

	ifstream fileBin;
	fileBin.open(fileName, ios::in | ios::binary);

	sKey.load(fileBin);
	pKey.load(fileBin);

	for(uint64_t i=0; i<encryptedImageData.size(); i++)
	{
		encryptedImageData.at(i).load(fileBin);
	}
	fileBin.close();
}

int ImageCiphertext::getNoiseBudget()
{
	Decryptor decryptor(imageContext, sKey);
	int noise =  decryptor.invariant_noise_budget(encryptedImageData[imageHeight]);	//renvoie une valeur parmis les ciphertexts de l'image

	cout << "current Noise Budget : " << noise << " bits" << endl << endl;

	return	noise;
	//normalement tous les ciphertexts ont le même bruit, puisqu'on ne fait pas encore de filtre à un certain endroit de l'image
}

void ImageCiphertext::printParameters()
{
    cout << endl << "/ Encryption parameters:" << endl;
    cout << "| poly_modulus: " << imageContext.poly_modulus().to_string() << endl;

    /*
    Print the size of the true (product) coefficient modulus
    */
    cout << "| coeff_modulus size: " 
        << imageContext.total_coeff_modulus().significant_bit_count() << " bits" << endl;

    cout << "| plain_modulus: " << imageContext.plain_modulus().value() << endl;
    cout << "\\ noise_standard_deviation: " << imageContext.noise_standard_deviation() << endl << endl;
}


//###########################################################################################################
//####################################### private classes ###################################################
//###########################################################################################################

Ciphertext ImageCiphertext::addRows(Ciphertext cipher, int position, int min, int max, const MemoryPoolHandle &pool)
{
	// cout << "		addRows from " << min << " to " << max << " on position " << position << endl;
    Evaluator evaluator(imageContext);
    PolyCRTBuilder crtbuilder(imageContext);

    vector<uint64_t> selector(crtbuilder.slot_count(), 0);
    Ciphertext tampon(pool);
    Plaintext selectorPlain(pool);

    int polyLength = imageContext.poly_modulus().significant_coeff_count() - 1;

    for(int coeff = min; coeff <= max; coeff++)
    {
        if(coeff == position) continue;

        //selection du coefficient
        selector[coeff] = 1;
        crtbuilder.compose(selector, selectorPlain);
        evaluator.multiply_plain(cipher, selectorPlain, tampon, pool);

        //shift du coefficient sur le slot position
        evaluator.rotate_rows(tampon, (coeff-position), gKey, pool);    //on donne le cipher, le nombre de shifts à faire (positif = gauche (?)) et la clé de shift

        if(((position < polyLength/2) && (coeff >= polyLength/2)) || ((position >= polyLength/2) && (coeff < polyLength/2))) 
        {
        	cout << "position : " << position << " coeff : " << coeff << endl;
        	evaluator.rotate_columns(tampon, gKey, pool);
        }



        //on additionne les deux cipher, avec les coeffs 1 et 2 du cipher maintenant à la même position dans cipher et tampon
        evaluator.add(cipher, tampon);

        //on oublie pas de reset le coefficient du vecteur sélecteur à zéro
        selector[coeff] = 0;
    }

    return cipher;
}

Ciphertext ImageCiphertext::convolute(int x, int y, int colorLayer, Filter filter)
{
	int sum = 0;

	Encryptor encryptor(imageContext, pKey);
	Evaluator evaluator(imageContext);
	PolyCRTBuilder crtbuilder(imageContext);

	Plaintext selectorPlain;
	vector<Ciphertext> tampons;

	int verticalOffset = (int) filter.getHeight()/2;
	int horizontalOffset = (int) filter.getWidth()/2;

	int XBegin, XEnd, YBegin, YEnd;
	(x < verticalOffset) ? (XBegin = -x) : (XBegin = -verticalOffset);
	(y < horizontalOffset) ? (YBegin = -y) : (YBegin = -horizontalOffset);
	(x < (imageHeight - verticalOffset)) ? (XEnd = verticalOffset) : (XEnd = (imageHeight - 1 - x));
	(y < (imageWidth - horizontalOffset)) ? (YEnd = horizontalOffset) : (YEnd = (imageWidth - 1 - y));

	for(int xOffset = XBegin; xOffset <= XEnd; xOffset++)		//travaille par ligne
	{
		Ciphertext tampon;
		vector<uint64_t> selector(crtbuilder.slot_count(), 0);

		for(int yOffset = YBegin; yOffset <= YEnd; yOffset++)	//travaille par colonne
		{
			selector[y+yOffset] = filter.getValue(verticalOffset + xOffset, horizontalOffset + yOffset);	//horizontal et vertical Offset sont aussi le milleu du tableau filter
			
			sum += filter.getValue(verticalOffset + xOffset, horizontalOffset + yOffset);
		}
		crtbuilder.compose(selector, selectorPlain);
		evaluator.multiply_plain(encryptedImageData[(x+xOffset)*3 + colorLayer], selectorPlain, tampon);
		tampons.push_back(tampon);
	}

	Ciphertext partialResult, result;
	evaluator.add_many(tampons, partialResult);		//ajoute les valeurs de chaque ligne dans une seule

	result = addRows(partialResult, y, y+YBegin, y+YEnd, MemoryPoolHandle::Global());	//ajoute les valeurs de chaque colonne dans une seule
	//result contient donc en y la somme de toutes les valeurs coefficientées par filter, mais contient également des sommes autour

	vector<uint64_t> selectorNew(crtbuilder.slot_count(), 0);	//permet de ne selectionner que le membre de result en Y qui nous intéresse
	selectorNew[y] = 1;	
	crtbuilder.compose(selectorNew, selectorPlain);
	evaluator.multiply_plain(result, selectorPlain);	//on sélectionne le membre du résult qui nous intéresse, et on supprime tous les autres

	normalisation[x][y][colorLayer] *= (float)1/sum;	//on actualise l'offset de normalisation sur le pixel traité

	return result;
}


Ciphertext ImageCiphertext::convolute2(int x, int y, int colorLayer, Filter filter)
{
	int sum = 0;

	Evaluator evaluator(imageContext);
	PolyCRTBuilder crtbuilder(imageContext);

	Plaintext selectorPlain;
	vector<Ciphertext> tampons;

	int verticalOffset = (int) filter.getHeight()/2;
	int horizontalOffset = (int) filter.getWidth()/2;

	for(int xOffset = -verticalOffset; xOffset <= verticalOffset; xOffset++)		//travaille par ligne
	{
		vector<Ciphertext> pixelsLine;
		Ciphertext line;
		int currentX;

		((x + xOffset) < 0) ? (currentX = 0) : (((x+xOffset) > imageHeight - 1) ? (currentX = imageHeight - 1) : (currentX = x + xOffset));

		for(int yOffset = -horizontalOffset; yOffset <= horizontalOffset; yOffset++)	//travaille par colonne
		{
			Ciphertext tampon;
			vector<uint64_t> selector(crtbuilder.slot_count(), 0);
			int currentY;

			((y + yOffset) < 0) ? (currentY = 0) : (((y+yOffset) > imageWidth - 1) ? (currentY = imageWidth - 1) : (currentY = y + yOffset));

			int mult = filter.getValue(verticalOffset + xOffset, horizontalOffset + yOffset);

			sum += mult;

			// cout << "mult : " << mult;

			(mult < 0) ? (selector[currentY] = -mult) : (selector[currentY] = mult);

			// cout << ", selector[y+yOffset] : " << selector[y+yOffset] << endl;

			crtbuilder.compose(selector, selectorPlain);
			if( mult != 0)
			{
				if(mult < 0)
				{
					evaluator.negate(encryptedImageData[(currentX)*3 + colorLayer], tampon);
					evaluator.multiply_plain(tampon, selectorPlain);
				}
				else if(mult > 0)
				{
					evaluator.multiply_plain(encryptedImageData[(currentX)*3 + colorLayer], selectorPlain, tampon);
				}

				pixelsLine.push_back(tampon);
			}
			
		}
		evaluator.add_many(pixelsLine, line);

		tampons.push_back(line);
	}

	Ciphertext partialResult, result;
	evaluator.add_many(tampons, partialResult);		//ajoute les valeurs de chaque ligne dans une seule

	int YBegin, YEnd;
	(y < horizontalOffset) ? (YBegin = -y) : (YBegin = -horizontalOffset);
	(y < (imageWidth - horizontalOffset)) ? (YEnd = horizontalOffset) : (YEnd = (imageWidth - 1 - y));

	result = addRows(partialResult, y, y+YBegin, y+YEnd, MemoryPoolHandle::Global());	//ajoute les valeurs de chaque colonne dans une seule
	//result contient donc en y la somme de toutes les valeurs coefficientées par filter, mais contient également des sommes autour

	vector<uint64_t> selectorNew(crtbuilder.slot_count(), 0);	//permet de ne selectionner que le membre de result en Y qui nous intéresse
	selectorNew[y] = 1;	
	crtbuilder.compose(selectorNew, selectorPlain);
	evaluator.multiply_plain(result, selectorPlain);	//on sélectionne le membre du résult qui nous intéresse, et on supprime tous les autres

	if(sum != 0)
	{
		normalisation[x][y][colorLayer] *= (float)1/sum;	//on actualise l'offset de normalisation sur le pixel traité
	}

	return result;
}

Ciphertext ImageCiphertext::convolute2Threaded(SEALContext context, int height, int width, int x, int y, int colorLayer, Filter filter, mutex &rmtx, const MemoryPoolHandle &pool)
{
	int sum = 0;

	Evaluator evaluator(context);
	PolyCRTBuilder crtbuilder(context);

	Plaintext selectorPlain(pool);
	vector<Ciphertext> tampons;

	int verticalOffset = (int) filter.getHeight()/2;
	int horizontalOffset = (int) filter.getWidth()/2;

	for(int xOffset = -verticalOffset; xOffset <= verticalOffset; xOffset++)		//travaille par ligne
	{
		vector<Ciphertext> pixelsLine;
		Ciphertext line(pool);
		int currentX;

		((x + xOffset) < 0) ? (currentX = 0) : (((x+xOffset) > height - 1) ? (currentX = height - 1) : (currentX = x + xOffset));

		for(int yOffset = -horizontalOffset; yOffset <= horizontalOffset; yOffset++)	//travaille par colonne
		{
			Ciphertext tampon(pool), data(pool);
			vector<uint64_t> selector(crtbuilder.slot_count(), 0);
			int currentY;

			((y + yOffset) < 0) ? (currentY = 0) : (((y+yOffset) > width - 1) ? (currentY = width - 1) : (currentY = y + yOffset));

			int mult = filter.getValue(verticalOffset + xOffset, horizontalOffset + yOffset);

			sum += mult;

			// cout << "mult : " << mult;

			(mult < 0) ? (selector[currentY] = -mult) : (selector[currentY] = mult);

			// cout << ", selector[y+yOffset] : " << selector[y+yOffset] << endl;

			crtbuilder.compose(selector, selectorPlain);
			if( mult != 0)
			{
				while(!rmtx.try_lock());
				data = encryptedImageData[(currentX)*3 + colorLayer];
				rmtx.unlock();

				if(mult < 0)
				{
					evaluator.negate(data, tampon);
					evaluator.multiply_plain(tampon, selectorPlain, pool);
				}
				else if(mult > 0)
				{
					evaluator.multiply_plain(data, selectorPlain, tampon, pool);
				}

				pixelsLine.push_back(tampon);
			}
			
		}
		evaluator.add_many(pixelsLine, line);

		tampons.push_back(line);
	}

	Ciphertext partialResult(pool), result(pool);
	evaluator.add_many(tampons, partialResult);		//ajoute les valeurs de chaque ligne dans une seule

	int YBegin, YEnd;
	(y < horizontalOffset) ? (YBegin = -y) : (YBegin = -horizontalOffset);
	(y < (width - horizontalOffset)) ? (YEnd = horizontalOffset) : (YEnd = (width - 1 - y));

	result = addRows(partialResult, y, y+YBegin, y+YEnd, pool);	//ajoute les valeurs de chaque colonne dans une seule
	//result contient donc en y la somme de toutes les valeurs coefficientées par filter, mais contient également des sommes autour

	vector<uint64_t> selectorNew(crtbuilder.slot_count(), 0);	//permet de ne selectionner que le membre de result en Y qui nous intéresse
	selectorNew[y] = 1;	
	crtbuilder.compose(selectorNew, selectorPlain);
	evaluator.multiply_plain(result, selectorPlain, pool);	//on sélectionne le membre du résult qui nous intéresse, et on supprime tous les autres

	if(sum != 0)
	{
		// while(!rmtx.try_lock());
		normalisation[x][y][colorLayer] *= (float)1/sum;	//on actualise l'offset de normalisation sur le pixel traité
		// rmtx.unlock();
	}

	return result;
}

void ImageCiphertext::initNorm()
{
	// normalisation = (float**) malloc(imageHeight*sizeof(*normalisation));

	// for(int i = 0; i < imageHeight; i++)
	// {
	// 	normalisation[i] = (float*) malloc(imageWidth*sizeof(**normalisation));
	// }

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

void ImageCiphertext::printLine(vector<uint64_t> vect)
{
	cout << "[";
	for(int i = 0; i < imageWidth; i++)
	{
		cout << vect[i] << " ";
	}
	cout << "]";
}