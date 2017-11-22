#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include <seal/seal.h>
#include "filter.cpp"
#include "plaintextImage.h"

using namespace std;
using namespace seal;

class ImageCiphertext
{

	public :
		ImageCiphertext(ImagePlaintext autre);

		ImageCiphertext(ImageCiphertext& autre);

		bool generateKeys();

		bool encrypt(ImagePlaintext autre);

		ImagePlaintext decrypt()
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


		bool negate()
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

		bool grey()
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

		bool applyFilter(Filter filter)
		{
			if(filter.validate() && getNoiseBudget() > 0)
			{
				cout << "applying filter :" << endl;
				filter.print();

				PolyCRTBuilder crtbuilder(imageContext);
				Evaluator evaluator(imageContext);
				vector<Ciphertext> newEncryptedData(imageHeight*3, Ciphertext());
				Ciphertext resultPixel, tampon;
				Plaintext selectorPlain;

				for(int x = 0; x < imageHeight; x++)	//travaille sur chaque ligne de l'image 
				{
					for(int y = 0; y < imageWidth; y++) //travaille sur chaque pixel 
					{
						for(int colorLayer = 0; colorLayer < 3; colorLayer++)	//travaille sur chaque layer de color
						{
							resultPixel = convolute(x, y, colorLayer, filter);
							vector<uint64_t> selector(crtbuilder.slot_count(), 1);

							selector[y] = 0;
							crtbuilder.compose(selector, selectorPlain);

							evaluator.multiply_plain(encryptedImageData[x*3+colorLayer], selectorPlain, tampon);

							evaluator.add(tampon, resultPixel, newEncryptedData[x*3+colorLayer]);
						}
						cout << "*";
						cout.flush();
					}
					cout << " " << x+1 << " lignes sur " << imageHeight << endl;
				}

				encryptedImageData = newEncryptedData;
			}
		}

		bool save(string fileName)
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

		bool load()
		{
			string fileName = "Ciphertext";

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

		uint32_t getDataSize()
		{
			uint32_t dataSize = encryptedImageData.size();
			return dataSize;
		}

		Ciphertext getDataAt(uint32_t index)
		{
			Ciphertext retCipher((const Ciphertext) encryptedImageData.at(index));
			return retCipher;
		}

		uint32_t getHeight()
		{
			uint32_t retHeight(imageHeight);
			return retHeight;
		}

		uint32_t getWidth()
		{
			uint32_t retWidth(imageWidth);
			return retWidth;
		}

		SEALContext getContext()
		{
			SEALContext retContext((const SEALContext) imageContext);
			return retContext;
		}

		PublicKey getPublicKey()
		{
			PublicKey pKeyRet(pKey);
			return pKeyRet;
		}

		SecretKey getSecretKey()
		{
			SecretKey sKeyRet(sKey);
			return sKeyRet;
		}

		GaloisKeys getGaloisKeys()
		{
			GaloisKeys gKeyRet(gKey);
			return gKeyRet;
		}

		int getNoiseBudget()
		{
			Decryptor decryptor(imageContext, sKey);
			int noise =  decryptor.invariant_noise_budget(encryptedImageData[imageHeight]);	//renvoie une valeur parmis les ciphertexts de l'image

			cout << "current Noise Budget : " << noise << " bits" << endl;

			return	noise;
			//normalement tous les ciphertexts ont le même bruit, puisqu'on ne fait pas encore de filtre à un certain endroit de l'image
		}

		void printParameters()
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

	private :
		Ciphertext addRows(Ciphertext cipher, int position, int min, int max)
		{
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

		    /*//partie pour annuler tous les termes du plaintext sauf celui à position
		    selector[position] = 1;
		    crtbuilder.compose(selector, selectorPlain);
		    evaluator.multiply_plain(cipher, selectorPlain);
		*/
		    return cipher;
		}

		Ciphertext convolute(int x, int y, int colorLayer, Filter filter)
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

			normalisation[x][y] *= (float)1/sum;	//on actualise l'offset de normalisation sur le pixel traité

			return result;
		}

		void initNorm()
		{
			normalisation = (float**) malloc(imageHeight*sizeof(*normalisation));

			for(int i = 0; i < imageHeight; i++)
			{
				normalisation[i] = (float*) malloc(imageWidth*sizeof(**normalisation));
			}

			for(int i = 0; i < imageHeight; i++)
			{
				for(int j = 0; j < imageWidth; j++)
				{
					// cout << "(" << i << ", " << j << ")" << "imageHeight : " << imageHeight << "imageWidth : " << imageWidth << endl;
					normalisation[i][j] = 1.0;
				}
			}
		}

		void updateNorm(float value)
		{
			for(int i = 0; i < imageHeight; i++)
			{
				for(int j = 0; j < imageWidth; j++)
				{
					normalisation[i][j] *= value;
				}
			}
		}

		bool verifyNormOver(float value)
		{
			bool result = true;

			for(int i =0; i < imageHeight; i++)
			{
				for(int j = 0; j > imageWidth; j++)
				{
					if(normalisation[i][j] < value)
					{
						result = false;
					}
				}
			}

			return result;
		}


		SEALContext imageContext;
		SecretKey sKey;
		PublicKey pKey;
		GaloisKeys gKey;
		uint32_t imageHeight, imageWidth;
		vector<Ciphertext> encryptedImageData;
		float **normalisation;
};