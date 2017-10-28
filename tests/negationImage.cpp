#include <fstream>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>

#include "seal.h"
#include "png-util.h"

using namespace std;
using namespace seal;


class ImagePlaintext
{
	public :
		ImagePlaintext(EncryptionParameters parameters, char* fileName)
		{
			parameters.validate();

			imageParameters = parameters;

			//methode à ajouter pour vérifier le fileName et l'image correspondante (si existante) et set les attributs imageWidth et imageHeight
			//pour le moment le set se fait dans PNGToImagePlaintext

			toPlaintext(fileName);
		}

		ImagePlaintext(EncryptionParameters parameters, uint32_t height, uint32_t width, vector<Plaintext> data)
		{
			parameters.validate();
			imageParameters = parameters;

			imageHeight = height;
			imageWidth = width;

			for(int i = 0; i < data.size(); i++)
			{
				imageData.push_back(data.at(i));
			}
		}

		bool toPlaintext(char* fileName)
		{
			PolyCRTBuilder crtbuilder(imageParameters);
			read_png_file(fileName);

			if(width > imageParameters.poly_modulus().significant_coeff_count() - 1)
				throw invalid_argument("poly_modulus doit être supérieur à la largeur de l'image");

			cout << "début d'encodage" << endl;

			imageWidth = width;
			imageHeight = height;

			vector<BigUInt> reds(crtbuilder.get_slot_count(), BigUInt(imageParameters.plain_modulus().bit_count(), static_cast<uint64_t>(0)));
			vector<BigUInt> greens(crtbuilder.get_slot_count(), BigUInt(imageParameters.plain_modulus().bit_count(), static_cast<uint64_t>(0)));
			vector<BigUInt> blues(crtbuilder.get_slot_count(), BigUInt(imageParameters.plain_modulus().bit_count(), static_cast<uint64_t>(0)));

			Plaintext redsPoly;
			Plaintext greensPoly;
			Plaintext bluesPoly;

			for(int i = 0; i < height; i++)
			{
				 png_bytep row = row_pointers[i];
				for(int j = 0; j < width; j++)
				{
					png_bytep px = &(row[j * 4]);

					reds[j] = px[0];
					greens[j] = px[1];
					blues[j] = px[2];
				}

				redsPoly = crtbuilder.compose(reds);
				greensPoly = crtbuilder.compose(greens);
				bluesPoly = crtbuilder.compose(blues);
				imageData.push_back(redsPoly);
				imageData.push_back(greensPoly);
				imageData.push_back(bluesPoly);
			}

			cout << "fin d'encodage" << endl;

			return 0;
		}

		bool toImage(char* fileName)
		{
			PolyCRTBuilder crtbuilder(imageParameters);

			cout << "début décodage" << endl;

			int height = imageHeight;
			int width = imageWidth;

			vector<BigUInt> reds(crtbuilder.get_slot_count(), BigUInt(imageParameters.plain_modulus().bit_count(), static_cast<uint64_t>(0)));
			vector<BigUInt> greens(crtbuilder.get_slot_count(), BigUInt(imageParameters.plain_modulus().bit_count(), static_cast<uint64_t>(0)));
			vector<BigUInt> blues(crtbuilder.get_slot_count(), BigUInt(imageParameters.plain_modulus().bit_count(), static_cast<uint64_t>(0)));

			for(int i = 0; i < height; i++)
			{
				png_bytep row = row_pointers[i];

				reds = crtbuilder.decompose(imageData.at(i * 3));
				greens = crtbuilder.decompose(imageData.at(i * 3 + 1));
				blues = crtbuilder.decompose(imageData.at(i * 3 + 2));

				for(int j = 0; j < width; j++)
				{
					png_bytep px = &(row[j * 4]);

					px[0] = (char)*reds[j].pointer();
					px[1] = (char)*greens[j].pointer();
					px[2] = (char)*blues[j].pointer();
				}
			}

			cout << "fin décodage" << endl;

			cout << "début écriture PNG" << endl;
			write_png_file(fileName);
			cout << "fin d'écriture PNG" << endl;

			return 0;
		}

		uint32_t getDataSize()
		{
			uint32_t dataSize = imageData.size();
			return dataSize;
		}

		Plaintext getDataAt(uint32_t index)
		{
			Plaintext retPlain((const Plaintext) imageData.at(index));
			return retPlain;
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

		EncryptionParameters getParameters()
		{
			EncryptionParameters retParameters((const EncryptionParameters) imageParameters);
			return retParameters;
		}

		string to_string()
		{
			string retString;

			for(int i = 0; i < imageData.size(); i++)
			{
				retString.append(imageData.at(i).to_string());
				retString.append("\n");
			}

			return retString;
		}

	private : 
		EncryptionParameters imageParameters;
		uint32_t imageHeight, imageWidth;
		vector<Plaintext> imageData;
};


class ImageCiphertext
{
	public :
		ImageCiphertext(ImagePlaintext autre) : publicKey(BigPolyArray())
		{
			EncryptionParameters autreParameters = autre.getParameters();
			autreParameters.validate();
			imageParameters = autreParameters;

			generateKeys();

			imageHeight = autre.getHeight();
			imageWidth = autre.getWidth();
		}

		bool generateKeys()
		{
			cout << "generating keys" << endl;

			KeyGenerator generator(imageParameters);
		    generator.generate();
		    secretKey = generator.secret_key();
		    publicKey = generator.public_key();

		    cout << "keys generated successfully" << endl;
		}

		bool encrypt(ImagePlaintext autre)
		{
			Encryptor encryptor(imageParameters, publicKey);
			Ciphertext cipherTampon = BigPolyArray();

			encryptedImageData.clear();

			cout << "début du cryptage image" << endl;

			for(uint64_t i = 0; i < autre.getDataSize(); i++)
			{
				cipherTampon = encryptor.encrypt(autre.getDataAt(i));
				encryptedImageData.push_back(cipherTampon);
			}

			cout << "fin du cryptage" << endl;
		}

		ImagePlaintext decrypt()
		{
			Decryptor decryptor(imageParameters, secretKey);
			vector<Plaintext> decryptedData;

			cout << "début du décryptage image" << endl;

			for(uint64_t i = 0; i < encryptedImageData.size(); i++)
			{
				decryptedData.push_back(decryptor.decrypt(encryptedImageData.at(i)));
			}

			cout << "fin décryptage" << endl;

			return ImagePlaintext(imageParameters, imageHeight, imageWidth, decryptedData);
		}

		// string to_string()
		// {
		// 	string retString;

		// 	for(uint64_t i = 0; i < encryptedImageData.size(); i++)
		// 	{
		// 		retString.append(encryptedImageData.at(i).to_string());
		// 		retString.append("\n");
		// 	}

		// 	return retString;
		// }


		bool negate()
		{
			uint64_t plainModulus = *imageParameters.plain_modulus().pointer();
			int dynamiqueValeursPlain = 256;

			Ciphertext cipherTampon = BigPolyArray();
			Ciphertext cipherTampon2 = BigPolyArray();

			Evaluator evaluator(imageParameters);
			PolyCRTBuilder crtbuilder(imageParameters);

			vector<BigUInt> reducteur(crtbuilder.get_slot_count(), BigUInt(imageParameters.plain_modulus().bit_count(), static_cast<uint64_t>(plainModulus - dynamiqueValeursPlain + 1)));

			Plaintext reduction = crtbuilder.compose(reducteur);

			cout << "beggining negate" << endl;

			for(uint64_t i = 0; i < encryptedImageData.size(); i++)
			{
				cipherTampon = evaluator.negate(encryptedImageData.at(i));
				cipherTampon2 = evaluator.sub_plain(cipherTampon, reduction);
				encryptedImageData.at(i) = cipherTampon2;
			}

			cout << "end of negate" << endl;

		}

	private :
		EncryptionParameters imageParameters;
		Plaintext secretKey;
		Ciphertext publicKey;
		uint32_t imageHeight, imageWidth;
		vector<Ciphertext> encryptedImageData;
};


int main(int argc, char* argv[])
{
	 if(argc < 2) abort();

	string polyModulus = "1x^1024 + 1";
    
	BigUInt coeffModulus = ChooserEvaluator::default_parameter_options().at(1024);

	int plainModulus = 65537;       //valeur marche pour toutes les puissances de 2 jusqu'à 8192 (poly_modulus)
                                    //attention, réduit significativement le bruit disponible (peut être compensé par un coeff modulus plus grand, mais réduit la sécurité (?))

    int dynamiqueValeursPlain = 256;    //peut être modifié si on travaille avec des valeurs comportant une autre dynamique (si on veux inverser des int par exemple)

	EncryptionParameters parameters;

	parameters.set_poly_modulus(polyModulus);
	parameters.set_coeff_modulus(coeffModulus);
	parameters.set_plain_modulus(plainModulus);

	parameters.validate();

	cout << "poly_modulus of parameters : " << parameters.poly_modulus().significant_coeff_count() << endl;	//pratique pour savoir quel est le poly_modulus !

	ImagePlaintext monImage(parameters, argv[1]);

	ofstream outFile;
	outFile.open("ImagePlaintext.txt", ios::out);
	outFile << monImage.to_string();
	outFile.close();


	ImageCiphertext imageCryptee(monImage);
	imageCryptee.encrypt(monImage);

	imageCryptee.negate();

	ImagePlaintext imageFinale = imageCryptee.decrypt();
	imageFinale.toImage("imageNegate.png");

	return 0;
}