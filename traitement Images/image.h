#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <chrono>

#include <seal/seal.h>
#include "filter.h"

using namespace std;
using namespace seal;

class ImageCiphertext;
class ImagePlaintext;

class ImageCiphertext
{

	public :

		ImageCiphertext(){};

		ImageCiphertext(ImageCiphertext& autre);

		ImageCiphertext(EncryptionParameters parameters, int height, int width, PublicKey pKey, GaloisKeys gKey, vector<Ciphertext> encryptedData);

		ImageCiphertext& operator=(const ImageCiphertext& assign);

		bool negate();

		bool grey();

		bool applyFilter(Filter filter, int numThread = 1);

		bool save(string fileName);

		bool load(string fileName);

		uint32_t getDataSize()
		{
			return encryptedImageData.size();
		}

		Ciphertext getDataAt(uint32_t index)
		{
			if(index >= encryptedImageData.size())
				throw std::out_of_range("index must be less than data size");
			return encryptedImageData.at(index);
		}

		vector<Ciphertext> getAllData()
		{
			return encryptedImageData;
		}

		uint32_t getHeight()
		{
			return imageHeight;
		}

		uint32_t getWidth()
		{
			return imageWidth;
		}

		EncryptionParameters getParameters()
		{
			return imageParameters;
		}

		PublicKey getPublicKey()
		{
			return pKey;
		}

		GaloisKeys getGaloisKeys()
		{
			return gKey;
		}

		float*** getNorm()
		{
			return normalisation;
		}

		void printParameters();

	private :
		Ciphertext addRows(SEALContext imageContext, Ciphertext cipher, int position, int min, int max, const MemoryPoolHandle &pool);

		Ciphertext convolute(SEALContext context, int height, int width, int x, int y, int colorLayer, Filter filter, mutex &rmtx, const MemoryPoolHandle &pool);

		void initNorm();

		void updateNorm(float value);

		bool verifyNormOver(float value);

		void printLine(vector<uint64_t> vect);

		EncryptionParameters imageParameters;
		PublicKey pKey;
		GaloisKeys gKey;
		uint32_t imageHeight, imageWidth;
		vector<Ciphertext> encryptedImageData;
		float ***normalisation;
};

class ImagePlaintext
{

	public :

		ImagePlaintext(){};

	/**
		crée un nouvel objet correspondant aux données d'une image sous forme de plaintext (CRT) appartenant à SEAL
		@param[in] parameters paramètres décidés en amont, et validés
		@param[in] fileName le nom du fichier à ouvrir (png)
	*/
		ImagePlaintext(const EncryptionParameters &parameters, char* fileName);

		ImagePlaintext(const EncryptionParameters &parameters, SecretKey sKey);

		bool generateKeys();

		bool encrypt(ImageCiphertext &destination);

		bool decrypt(ImageCiphertext &source);

	/**
		lit une image png pour contruire un objet ImagePlaintext contenant les données de l'image.
		les données sont ordonnées dans un vecteur contenant des polynomes Plaintext, eux même contenant les coefficient d'un couleur
		d'une ligne de l'image
		càd que chaque Plaintext du vecteur de données contient les soit les rouges, soit les verts, soit les bleus d'une ligne de l'image
		dans cet ordre.
		à cet effet, le poly_modulus des paramètres choisis doit être supérieur à la largeur de l'image 
	*/
		bool toPlaintext(char* fileName);

	/**
		crée une nouvelle image d'apès les données contenues dans l'objet ImagePlaintext
	*/
		bool toImage(string fileName);

	/**
		revoie la taille u vecteur contenant les données de l'image
		(renvoie le nombre de Plaintexts, soit le nombre de lignes de l'image fois trois)
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
		EncryptionParameters getParameters()
		{
			EncryptionParameters retParameters((const EncryptionParameters) imageParameters);
			return retParameters;
		}


	/**
		renvoie un string comprenant tous les Plaintexts de l'image les uns après les autres (avec un retour à la ligne)
	*/
		string to_string();

		void printParameters();

	private : 
		void initNorm();

		void copyNorm(float ***norm);

		EncryptionParameters imageParameters;
		SecretKey sKey;
		PublicKey pKey;
		GaloisKeys gKey;
		uint32_t imageHeight, imageWidth;
		vector<Plaintext> imageData;
		float ***normalisation;
};