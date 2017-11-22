#include "image.h"
#include "png-util.h"

ImagePlaintext::ImagePlaintext(const SEALContext &context, char* fileName) : imageContext(context)
{

	//methode à ajouter pour vérifier le fileName et l'image correspondante (si existante) et set les attributs imageWidth et imageHeight
	//pour le moment le set se fait dans PNGToImagePlaintext

	toPlaintext(fileName);
}

ImagePlaintext::ImagePlaintext(const SEALContext &context, uint32_t height, uint32_t width, float ***normalisation, vector<Plaintext> data) : imageContext(context)
{
	imageHeight = height;
	imageWidth = width;
	initNorm();
	copyNorm(normalisation);

	for(int i = 0; i < data.size(); i++)
	{
		imageData.push_back(data.at(i));
	}
}

bool ImagePlaintext::toPlaintext(char* fileName)
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

bool ImagePlaintext::toImage(string fileName)
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

			cout << "red[" << i << "][" << j << "] = " << reds[j] << "x" << normalisation[i][j][0] << endl;
			px[0] = (int)reds[j]*normalisation[i][j][0];
			cout << "green[" << i << "][" << j << "] = " << greens[j] << "x" << normalisation[i][j][1] << endl;
			px[1] = (int)greens[j]*normalisation[i][j][1];
			cout << "blue[" << i << "][" << j << "] = " << blues[j] << "x" << normalisation[i][j][2] << endl;
			px[2] = (int)blues[j]*normalisation[i][j][2];
		}
	}

	cout << "fin décodage" << endl;

	cout << "début écriture PNG" << endl;
	write_png_file(&fileName[0u]);
	cout << "fin d'écriture PNG" << endl;

	return 0;
}

string ImagePlaintext::to_string()
{
	string retString;

	for(int i = 0; i < imageData.size(); i++)
	{
		retString.append(imageData.at(i).to_string());
		retString.append("\n");
	}

	return retString;
}

void ImagePlaintext::printParameters()
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


//###################################################################################################################
//############################################ private classes ######################################################
//###################################################################################################################

void ImagePlaintext::initNorm()
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
}

void ImagePlaintext::copyNorm(float ***norm)
{
	for(int i = 0; i < imageHeight; i++)
	{
		for(int j = 0; j < imageWidth; j++)
		{
			for(int k = 0; k < 3; k++)
			{
				normalisation[i][j][k] = norm[i][j][k];
			}
		}
	}
}