#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include <seal/seal.h>

using namespace std;
using namespace seal;

class ImageCiphertext
{

	public :
		ImageCiphertext(ImagePlaintext autre) : imageContext(autre.getContext()), operations()
		{
			pKey = PublicKey();
			sKey = SecretKey();
			// imageContext = autre.getContext();

			generateKeys();

			imageHeight = autre.getHeight();
			imageWidth = autre.getWidth();
		}

		ImageCiphertext(ImageCiphertext& autre) : imageContext(autre.getContext()), operations()
		{
			pKey = PublicKey();
			sKey = SecretKey();
			// imageContext = autre.getContext();

			imageWidth = autre.getWidth();
			imageHeight = autre.getHeight();

			encryptedImageData.resize(autre.getDataSize(), Ciphertext());
		}

		bool generateKeys()
		{
			cout << "generating keys" << endl;

			KeyGenerator generator(imageContext);
		    sKey = generator.secret_key();
		    pKey = generator.public_key();

		    cout << "keys generated successfully" << endl;
		}

		bool encrypt(ImagePlaintext autre)
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

			return ImagePlaintext(imageContext, imageHeight, imageWidth, operations, decryptedData);
		}


		bool negate()
		{
			if(!operations.grey)
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

				operations.negate = true;

				cout << "end of negate" << endl;
			}
			else
			{
				cout << "negation impossible after greying" << endl;
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

			operations.grey = true;

			cout << "end of greying" << endl;
		}

		bool save()
		{
			string fileName = "Ciphertext";

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

		Op getOperations()
		{
			Op retOp(operations);
			return retOp;
		}

		void printOperations()
		{
			cout << endl << boolalpha
				<< "negation of picture : " << operations.negate << endl
				<< "greying of picture : " << operations.grey << endl
				<< endl;
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
		SEALContext imageContext;
		SecretKey sKey;
		PublicKey pKey;
		uint32_t imageHeight, imageWidth;
		vector<Ciphertext> encryptedImageData;
		Op operations;
};