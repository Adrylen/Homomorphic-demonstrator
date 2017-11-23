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

    cout << "keys generated successfully" << endl;
}

bool ImageCiphertext::encrypt(ImagePlaintext autre)
{
	Encryptor encryptor(imageContext, pKey);
	Ciphertext cipherTampon = Ciphertext();

	encryptedImageData.clear();

	cout << "début du cryptage image" << endl;

	for(uint64_t i = 0; i < autre.getDataSize(); i++)
	{
		encryptor.encrypt(autre.getDataAt(i), cipherTampon);
		encryptedImageData.push_back(cipherTampon);
	}

	cout << "fin du cryptage" << endl;
}

ImagePlaintext ImageCiphertext::decrypt()
{
	Decryptor decryptor(imageContext, sKey);
	vector<Plaintext> decryptedData;
	Plaintext plainTampon = Plaintext();

	cout << "début du décryptage image" << endl;

	for(uint64_t i = 0; i < encryptedImageData.size(); i++)
	{
		decryptor.decrypt(encryptedImageData.at(i), plainTampon);
		decryptedData.push_back(plainTampon);
	}

	cout << "fin décryptage" << endl;

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

		for(uint64_t i = 0; i < encryptedImageData.size(); i++)
		{
			evaluator.negate(encryptedImageData.at(i));
			evaluator.sub_plain(encryptedImageData.at(i), reduction);
		}

		cout << "end of negate" << endl;
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

	cout << "end of greying" << endl;
}

bool ImageCiphertext::applyFilter(Filter filter)
{
	if(filter.validate() && getNoiseBudget() > 0)
	{
		cout << "applying filter :" << endl;
		filter.print();

		PolyCRTBuilder crtbuilder(imageContext);
		Evaluator evaluator(imageContext);
		vector<Ciphertext> newEncryptedData(imageHeight*3, Ciphertext());
		vector<Ciphertext> pixelResults;
		Ciphertext resultPixel;
		Plaintext selectorPlain;

		for(int x = 0; x < imageHeight; x++)	//travaille sur chaque ligne de l'image 
		{
			for(int colorLayer = 0; colorLayer < 3; colorLayer++) //travaille sur chaque layer de couleur 
			{
				pixelResults.clear();

				for(int y = 0; y < imageWidth; y++)	//travaille sur chaque pixel de la ligne courante
				{
					pixelResults.push_back(convolute2(x, y, colorLayer, filter));
				}

				evaluator.add_many(pixelResults, newEncryptedData[x*3+colorLayer]);
			}
			cout << x+1 << " lignes sur " << imageHeight << endl;
		}

		encryptedImageData = newEncryptedData;
	}
}

bool ImageCiphertext::save(string fileName)
{

	cout << "début de sauvegarde du fichier crypté" << endl;

	ofstream fileBin;
	fileBin.open(fileName, ios::out | ios::binary);

	sKey.save(fileBin);
	pKey.save(fileBin);

	for(uint64_t i=0; i<encryptedImageData.size(); i++)
	{
		encryptedImageData.at(i).save(fileBin);
	}
	fileBin.close();

	cout << "fin de la sauvegarde" << endl;
}

bool ImageCiphertext::load(string fileName)
{
	cout << "début de chargement du fichier crypté" << endl;

	ifstream fileBin;
	fileBin.open(fileName, ios::in | ios::binary);

	sKey.load(fileBin);
	pKey.load(fileBin);

	for(uint64_t i=0; i<encryptedImageData.size(); i++)
	{
		encryptedImageData.at(i).load(fileBin);
	}
	fileBin.close();

	cout << "fin du chargement" << endl;
}

int ImageCiphertext::getNoiseBudget()
{
	Decryptor decryptor(imageContext, sKey);
	int noise =  decryptor.invariant_noise_budget(encryptedImageData[imageHeight]);	//renvoie une valeur parmis les ciphertexts de l'image

	cout << "current Noise Budget : " << noise << " bits" << endl;

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
    cout << "\\ noise_standard_deviation: " << imageContext.noise_standard_deviation() << endl;
    cout << endl;
}


//###########################################################################################################
//####################################### private classes ###################################################
//###########################################################################################################

Ciphertext ImageCiphertext::addRows(Ciphertext cipher, int position, int min, int max)
{
	// cout << "		addRows from " << min << " to " << max << " on position " << position << endl;
    Evaluator evaluator(imageContext);
    PolyCRTBuilder crtbuilder(imageContext);

    vector<uint64_t> selector(crtbuilder.slot_count(), 0);
    Ciphertext tampon;
    Plaintext selectorPlain;
    
    for(int coeff = min; coeff <= max; coeff++)
    {
        if(coeff == position) continue;

        //selection du coefficient
        selector[coeff] = 1;
        crtbuilder.compose(selector, selectorPlain);
        evaluator.multiply_plain(cipher, selectorPlain, tampon);

        //shift du coefficient sur le slot position
        evaluator.rotate_rows(tampon, (coeff-position), gKey);    //on donne le cipher, le nombre de shifts à faire (positif = gauche (?)) et la clé de shift

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

	result = addRows(partialResult, y, y+YBegin, y+YEnd);	//ajoute les valeurs de chaque colonne dans une seule
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

	Encryptor encryptor(imageContext, pKey);
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

	result = addRows(partialResult, y, y+YBegin, y+YEnd);	//ajoute les valeurs de chaque colonne dans une seule
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