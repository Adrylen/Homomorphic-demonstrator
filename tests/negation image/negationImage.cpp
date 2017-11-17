#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include <seal/seal.h>
#include "png-util.h"

using namespace std;
using namespace seal;

struct op
{
	bool negate;
	bool grey;
};


class ImagePlaintext
{
	public :
	/**
		crée un nouvel objet correspondant aux données d'une image sous forme de plaintext (CRT) appartenant à SEAL
		@param[in] parameters paramètres décidés en amont, et validés
		@param[in] fileName le nom du fichier à ouvrir (png)
	*/
		ImagePlaintext(const SEALContext &context, char* fileName) : imageContext(context), operations{false, false}
		{

			//methode à ajouter pour vérifier le fileName et l'image correspondante (si existante) et set les attributs imageWidth et imageHeight
			//pour le moment le set se fait dans PNGToImagePlaintext

			toPlaintext(fileName);
		}

	/**
		contructeur utilisé pour copier les données décryptées d'un objet ImageCiphertext dans un objet de type ImagePlaintext
	*/
		ImagePlaintext(const SEALContext &context, uint32_t height, uint32_t width, op operationsDone, vector<Plaintext> data) : imageContext(context)
		{
			operations = operationsDone;
			imageHeight = height;
			imageWidth = width;

			for(int i = 0; i < data.size(); i++)
			{
				imageData.push_back(data.at(i));
			}
		}

	/**
		lit une image png pour contruire un objet ImagePlaintext contenant les données de l'image.
		les données sont ordonnées dans un vecteur contenant des polynomes Plaintext, eux même contenant les coefficient d'un couleur
		d'une ligne de l'image
		càd que chaque Plaintext du vecteur de données contient les soit les rouges, soit les verts, soit les bleus d'une ligne de l'image
		dans cet ordre.
		à cet effet, le poly_modulus des paramètres choisis doit être supérieur à la largeur de l'image 
	*/
		bool toPlaintext(char* fileName)
		{
			PolyCRTBuilder crtbuilder(imageContext);
			read_png_file(fileName);

			if(width > imageContext.poly_modulus().significant_coeff_count() - 1)
				throw invalid_argument("poly_modulus doit être supérieur à la largeur de l'image");

			cout << "début d'encodage" << endl;

			imageWidth = width;
			imageHeight = height;

			vector<uint64_t> reds(crtbuilder.slot_count(), 0);
			vector<uint64_t> greens(crtbuilder.slot_count(), 0);
			vector<uint64_t> blues(crtbuilder.slot_count(), 0);

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

				crtbuilder.compose(reds, redsPoly);
				crtbuilder.compose(greens, greensPoly);
				crtbuilder.compose(blues, bluesPoly);
				imageData.push_back(redsPoly);
				imageData.push_back(greensPoly);
				imageData.push_back(bluesPoly);
			}

			cout << "fin d'encodage" << endl;

			return 0;
		}
	/**
		crée une nouvelle image d'apès les données contenues dans l'objet ImagePlaintext
	*/
		bool toImage(char* fileName)
		{
			PolyCRTBuilder crtbuilder(imageContext);

			cout << "début décodage" << endl;

			int height = imageHeight;
			int width = imageWidth;

			vector<uint64_t> reds(crtbuilder.slot_count(), 0);
			vector<uint64_t> greens(crtbuilder.slot_count(), 0);
			vector<uint64_t> blues(crtbuilder.slot_count(), 0);

			if(operations.grey)
			{
				for(int i = 0; i < height; i++)
				{
					png_bytep row = row_pointers[i];

					crtbuilder.decompose(imageData.at(i * 3), reds);
					crtbuilder.decompose(imageData.at(i * 3 + 1), greens);
					crtbuilder.decompose(imageData.at(i * 3 + 2), blues);

					for(int j = 0; j < width; j++)
					{
						png_bytep px = &(row[j * 4]);

						px[0] = (int)reds[j]/100;
						px[1] = (int)greens[j]/100;
						px[2] = (int)blues[j]/100;
					}
				}
			}
			else
			{
				for(int i = 0; i < height; i++)
				{
					png_bytep row = row_pointers[i];

					crtbuilder.decompose(imageData.at(i * 3), reds);
					crtbuilder.decompose(imageData.at(i * 3 + 1), greens);
					crtbuilder.decompose(imageData.at(i * 3 + 2), blues);

					for(int j = 0; j < width; j++)
					{
						png_bytep px = &(row[j * 4]);

						px[0] = reds[j];
						px[1] = greens[j];
						px[2] = blues[j];
					}
				}
			}

			cout << "fin décodage" << endl;

			cout << "début écriture PNG" << endl;
			write_png_file(fileName);
			cout << "fin d'écriture PNG" << endl;

			return 0;
		}

	/**
		revoie la taille u vecteur contenant les données de l'image
		(revoie le nombre de Plaintexts, soit le nombre de lignes de l'image fois trois)
	*/
		uint32_t getDataSize()
		{
			uint32_t dataSize = imageData.size();
			return dataSize;
		}

	/**
		renvoie le Plaintext des données à l'indice index
		soit un Plaintext contenant la ligne des rouges, des verts ou des bleus d'une ligne
	*/
		Plaintext getDataAt(uint32_t index)
		{
			Plaintext retPlain((const Plaintext) imageData.at(index));
			return retPlain;
		}

	/**
		renvoie la hauteur de l'image
	*/
		uint32_t getHeight()
		{
			uint32_t retHeight(imageHeight);
			return retHeight;
		}

	/**
		renvoie la largeur de l'image
	*/
		uint32_t getWidth()
		{
			uint32_t retWidth(imageWidth);
			return retWidth;
		}

	/**
		renvoie les paramètres associés à ImagePlaintext
	*/
		SEALContext getContext()
		{
			SEALContext retContext((const SEALContext) imageContext);
			return retContext;
		}

		op getOperations()
		{
			op retOp(operations);
			return retOp;
		}

	/**
		renvoie un string comprenant tous les Plaintexts de l'image les uns après les autres (avec un retour à la ligne)
	*/
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
		uint32_t imageHeight, imageWidth;
		vector<Plaintext> imageData;
		op operations;
};


class ImageCiphertext
{
	public :
		ImageCiphertext(ImagePlaintext autre) : imageContext(autre.getContext()), operations{false, false}
		{
			pKey = PublicKey();
			sKey = SecretKey();
			// imageContext = autre.getContext();

			generateKeys();

			imageHeight = autre.getHeight();
			imageWidth = autre.getWidth();
		}

		ImageCiphertext(ImageCiphertext& autre) : imageContext(autre.getContext()), operations{false, false}
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

		op getOperations()
		{
			op retOp(operations);
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
		op operations;
};


int main(int argc, char* argv[])
{
	 if(argc < 2) abort();

	string polyModulus = "1x^1024 + 1";
    
	auto coeffModulus = coeff_modulus_128(2048);

	int plainModulus = 40961;       //valeur marche pour toutes les puissances de 2 jusqu'à 8192 (poly_modulus)
                                    //attention, réduit significativement le bruit disponible (peut être compensé par un coeff modulus plus grand, mais réduit la sécurité (?))

    int dynamiqueValeursPlain = 256;    //peut être modifié si on travaille avec des valeurs comportant une autre dynamique (si on veux inverser des int par exemple)

	EncryptionParameters parameters;

	parameters.set_poly_modulus(polyModulus);
	parameters.set_coeff_modulus(coeffModulus);
	parameters.set_plain_modulus(plainModulus);

	SEALContext context(parameters);

	auto qualifiers = context.qualifiers();
    cout << "Batching enabled: " << boolalpha << qualifiers.enable_batching << endl;

	ImagePlaintext monImage(context, argv[1]);
	monImage.printParameters();
	monImage.printOperations();

	ImageCiphertext imageCryptee(monImage);

	imageCryptee.encrypt(monImage);
	ImageCiphertext imageLoaded(imageCryptee);	//créée en tant que copie de l'imageCryptée

	imageCryptee.save();
	imageLoaded.load();

	imageLoaded.grey();
	imageLoaded.printOperations();

	ImagePlaintext imageFinale = imageLoaded.decrypt();
	imageFinale.printOperations();

	imageFinale.toImage("imageNegate.png");

	return 0;
}
