#include "image.h"
#include "png-util.h"

ImagePlaintext::ImagePlaintext(const EncryptionParameters &parameters, char* fileName)
{

	//methode à ajouter pour vérifier le fileName et l'image correspondante (si existante) et set les attributs imageWidth et imageHeight
	//pour le moment le set se fait dans PNGToImagePlaintext

	imageParameters = parameters;

	toPlaintext(fileName);

	generateKeys();

	initNorm();
}

ImagePlaintext::ImagePlaintext(const EncryptionParameters &parameters, SecretKey sKey)
{
	imageParameters = parameters;
	this->sKey = sKey;
	initNorm();
}

bool ImagePlaintext::generateKeys()
{
	cout << "generating keys" << endl;

	SEALContext context(imageParameters);

	KeyGenerator generator(context);
    sKey = generator.secret_key();
    pKey = generator.public_key();
    generator.generate_galois_keys(30, gKey);	//attention, le DBC (premier paramètre) devra être adapté en fonction des opérations

    cout << "keys generated successfully" << endl << endl;
}

bool ImagePlaintext::encrypt(ImageCiphertext &destination)
{
	cout << "début encryption" << endl;
	SEALContext imageContext(imageParameters);

	Encryptor encryptor(imageContext, pKey);
	Ciphertext cipherTampon = Ciphertext();

	vector<Ciphertext> encryptedImageData;

	cout << "début du cryptage image" << endl;

	auto timeStart = chrono::high_resolution_clock::now();

	for(uint64_t i = 0; i < imageData.size(); i++)
	{
		encryptor.encrypt(imageData.at(i), cipherTampon);
		encryptedImageData.push_back(cipherTampon);
	}

	auto timeStop = chrono::high_resolution_clock::now();

	cout << "--> fin du cryptage: " << chrono::duration_cast<chrono::milliseconds>(timeStop - timeStart).count() << " milliseconds" << endl << endl;

	destination = ImageCiphertext(imageParameters, imageHeight, imageWidth, pKey, gKey, encryptedImageData); 
}

bool ImagePlaintext::decrypt(ImageCiphertext &source)
{
	this->imageHeight = source.getHeight();
	this->imageWidth = source.getWidth();
	this->normalisation = source.getNorm();

	SEALContext imageContext(imageParameters);
	Decryptor decryptor(imageContext, sKey);
	vector<Ciphertext> encryptedData = source.getAllData();
	Plaintext plainTampon = Plaintext();
	this->imageData.clear();

	cout << "début du décryptage image" << endl;

	auto timeStart = chrono::high_resolution_clock::now();

	for(uint64_t i = 0; i < encryptedData.size(); i++)
	{
		decryptor.decrypt(encryptedData.at(i), plainTampon);
		this->imageData.push_back(plainTampon);
	}

	auto timeStop = chrono::high_resolution_clock::now();

	cout << "--> fin décryptage: " << chrono::duration_cast<chrono::milliseconds>(timeStop - timeStart).count() << " milliseconds" << endl << endl;
}

bool ImagePlaintext::toPlaintext(char* fileName)
{
	SEALContext imageContext(imageParameters);
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
	SEALContext imageContext(imageParameters);
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

			// cout << "red[" << i << "][" << j << "] = " << reds[j] << "x" << normalisation[i][j][0] << endl;
			px[0] = (int)reds[j]*normalisation[i][j][0];
			// cout << "green[" << i << "][" << j << "] = " << greens[j] << "x" << normalisation[i][j][1] << endl;
			px[1] = (int)greens[j]*normalisation[i][j][1];
			// cout << "blue[" << i << "][" << j << "] = " << blues[j] << "x" << normalisation[i][j][2] << endl;
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
	SEALContext imageContext(imageParameters);
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
	cout << norm;
	cout << "1";
	for(int i = 0; i < imageHeight; i++)
	{
		cout << "2";
		for(int j = 0; j < imageWidth; j++)
		{
			cout << "3";
			for(int k = 0; k < 3; k++)
			{
				cout << norm[i][j][k];
				normalisation[i][j][k] = norm[i][j][k];
			}
		}
	}
}