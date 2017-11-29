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



class ImagePlaintext
{

	public :
	/**
		crée un nouvel objet correspondant aux données d'une image sous forme de plaintext (CRT) appartenant à SEAL
		@param[in] parameters paramètres décidés en amont, et validés
		@param[in] fileName le nom du fichier à ouvrir (png)
	*/
		ImagePlaintext(const SEALContext &context, char* fileName);
	/**
		contructeur utilisé pour copier les données décryptées d'un objet ImageCiphertext dans un objet de type ImagePlaintext
	*/
		ImagePlaintext(const SEALContext &context, uint32_t height, uint32_t width, float ***normalisation, vector<Plaintext> data);

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
		SEALContext getContext()
		{
			SEALContext retContext((const SEALContext) imageContext);
			return retContext;
		}


	/**
		renvoie un string comprenant tous les Plaintexts de l'image les uns après les autres (avec un retour à la ligne)
	*/
		string to_string();

		void printParameters();

	private : 
		void initNorm();

		void copyNorm(float ***norm);

		SEALContext imageContext;
		uint32_t imageHeight, imageWidth;
		vector<Plaintext> imageData;
		float ***normalisation;
};





class ImageCiphertext
{

	public :
		ImageCiphertext(ImagePlaintext autre);

		ImageCiphertext(ImageCiphertext& autre);

		bool generateKeys();

		bool encrypt(ImagePlaintext autre);

		ImagePlaintext decrypt();

		bool negate();

		bool grey();

		bool applyFilter(Filter filter);

		bool applyFilterThreaded(Filter filter, int numThread);

		bool save(string fileName);

		bool load(string fileName);

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

		int getNoiseBudget();

		void printParameters();

	private :
		Ciphertext addRows(Ciphertext cipher, int position, int min, int max, const MemoryPoolHandle &pool);

		Ciphertext convolute(int x, int y, int colorLayer, Filter filter);

		Ciphertext convolute2(int x, int y, int colorLayer, Filter filter);

		Ciphertext convolute2Threaded(SEALContext context, int height, int width, int x, int y, int colorLayer, Filter filter, mutex &rmtx, const MemoryPoolHandle &pool);

		void initNorm();

		void updateNorm(float value);

		bool verifyNormOver(float value);

		void printLine(vector<uint64_t> vect);

		SEALContext imageContext;
		SecretKey sKey;
		PublicKey pKey;
		GaloisKeys gKey;
		uint32_t imageHeight, imageWidth;
		vector<Ciphertext> encryptedImageData;
		float ***normalisation;
};




