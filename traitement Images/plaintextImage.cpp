#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include <seal/seal.h>
#include "png-util.h"
#include "filter.cpp"

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
		ImagePlaintext(const SEALContext &context, char* fileName) : imageContext(context)
		{

			//methode à ajouter pour vérifier le fileName et l'image correspondante (si existante) et set les attributs imageWidth et imageHeight
			//pour le moment le set se fait dans PNGToImagePlaintext

			toPlaintext(fileName);
		}

	/**
		contructeur utilisé pour copier les données décryptées d'un objet ImageCiphertext dans un objet de type ImagePlaintext
	*/
		ImagePlaintext(const SEALContext &context, uint32_t height, uint32_t width, float normalisation, vector<Plaintext> data) : imageContext(context)
		{
			this->normalisation = normalisation;
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

			for(int i = 0; i < height; i++)
			{
				png_bytep row = row_pointers[i];

				crtbuilder.decompose(imageData.at(i * 3), reds);
				crtbuilder.decompose(imageData.at(i * 3 + 1), greens);
				crtbuilder.decompose(imageData.at(i * 3 + 2), blues);

				for(int j = 0; j < width; j++)
				{
					png_bytep px = &(row[j * 4]);

					px[0] = (int)reds[j]*normalisation;
					px[1] = (int)greens[j]*normalisation;
					px[2] = (int)blues[j]*normalisation;
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
		float normalisation;
};