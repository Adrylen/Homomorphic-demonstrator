#include "image.h"
#include "png-util.h"

ImagePlaintext::ImagePlaintext(const EncryptionParameters &parameters, char* fileName)
{
	this->imageParameters = parameters;

	toPlaintext(fileName);

	generateKeys();
}

ImagePlaintext::ImagePlaintext(const EncryptionParameters &parameters, SecretKey sKey)
{
	imageParameters = parameters;
	this->sKey = sKey;
}

void ImagePlaintext::encrypt(ImageCiphertext &destination)
{
	SEALContext imageContext(imageParameters);

	Encryptor encryptor(imageContext, pKey);
	Decryptor decryptor(imageContext, sKey);
	Ciphertext cipherTampon = Ciphertext();

	vector<Ciphertext> encryptedImageData;

	cout << "beginning image encryption" << endl;

	auto timeStart = chrono::high_resolution_clock::now();

	for(uint64_t i = 0; i < imageData.size(); i++)
	{
		encryptor.encrypt(imageData.at(i), cipherTampon);
		encryptedImageData.push_back(cipherTampon);
	}

	auto timeStop = chrono::high_resolution_clock::now();

	cout << "--> encryption finished: " << chrono::duration_cast<chrono::milliseconds>(timeStop - timeStart).count() << " milliseconds" << endl;
	cout << "available noise budget: " << decryptor.invariant_noise_budget(encryptedImageData.at(1)) << " bits" << endl << endl;

	destination = ImageCiphertext(imageParameters, imageHeight, imageWidth, pKey, gKey, encryptedImageData); 
}

void ImagePlaintext::decrypt(ImageCiphertext &source)
{
	this->imageHeight = source.getHeight();
	this->imageWidth = source.getWidth();
	this->normalisation = source.getNorm();

	SEALContext imageContext(imageParameters);
	Decryptor decryptor(imageContext, sKey);
	vector<Ciphertext> encryptedData = source.getAllData();
	Plaintext plainTampon = Plaintext();
	this->imageData.clear();

	cout << "remaining noise budget: " << decryptor.invariant_noise_budget(encryptedData.at(1)) << " bits" << endl;
	cout << "beginning decryption" << endl;

	auto timeStart = chrono::high_resolution_clock::now();

	for(uint64_t i = 0; i < encryptedData.size(); i++)
	{
		decryptor.decrypt(encryptedData.at(i), plainTampon);
		this->imageData.push_back(plainTampon);
	}

	auto timeStop = chrono::high_resolution_clock::now();

	cout << "--> end of decryption: " << chrono::duration_cast<chrono::milliseconds>(timeStop - timeStart).count() << " milliseconds" << endl << endl;
}

void ImagePlaintext::toPlaintext(char* fileName)
{
	SEALContext imageContext(imageParameters);
	PolyCRTBuilder crtbuilder(imageContext);
	read_png_file(fileName);

	if(width > imageContext.poly_modulus().significant_coeff_count() - 1)
		throw invalid_argument("poly_modulus must be over image width");

	cout << "beginning encoding" << endl;

	imageWidth = width;
	imageHeight = height;

	//calculating offset to apply to values to put them at the center of the plain modulus
	uint64_t plainModulus = *imageContext.plain_modulus().pointer();
	int offset = (int)(plainModulus - 255) / 2;

	cout << "offset applied : " << offset << endl;

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

			//taking pixel color value, and adding offset
			reds[j] = px[0] + offset;
			greens[j] = px[1] + offset;
			blues[j] = px[2] + offset;
		}

		//every value of a line of the image is stored in a ciphertext using CRT batching (see SEAL documentation)
		//the data is always sotred as such : a ciphertext for red values of line, then for green values, and then for blue values
		//then next line of the image
		//as such, there is imageHeight*3 ciphertexts in data
		crtbuilder.compose(reds, redsPoly);
		crtbuilder.compose(greens, greensPoly);
		crtbuilder.compose(blues, bluesPoly);
		imageData.push_back(redsPoly);
		imageData.push_back(greensPoly);
		imageData.push_back(bluesPoly);
	}

	cout << "end of encoding" << endl;
}

void ImagePlaintext::toImage(string fileName)
{
	SEALContext imageContext(imageParameters);
	PolyCRTBuilder crtbuilder(imageContext);

	cout << "beginning decoding" << endl;

	int height = imageHeight;
	int width = imageWidth;

	//calculating offset to be removed
	uint64_t plainModulus = *imageContext.plain_modulus().pointer();
	int offset = (int)(plainModulus - 255) / 2;

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

			//for each value, the offset is removed (thus, the value can be negative), then normalisation is applied
			int pix0 = (int)((reds[j]-offset)*normalisation[i][j][0]);
			//makes sure that the value is taken back to pixel dynamics
			(pix0 < 0) ? (pix0 = 0) : (pix0 = pix0);
			(pix0 > 255) ? (pix0 = 255) : (pix0 = pix0);
			px[0] = pix0;
			// cout << "(" << reds[j] << " - " << offset << ")*" << normalisation[i][j][0] << ", px[" << i << "][" << j << "][0] = " << (int)px[0] << endl;	//DEBUG

			int pix1 = (int)((greens[j]-offset)*normalisation[i][j][1]);
			(pix1 < 0) ? (pix1 = 0) : (pix1 = pix1);
			(pix1 > 255) ? (pix1 = 255) : (pix1 = pix1);
			px[1] = pix1;
			// cout << "(" << greens[j] << " - " << offset << ")*" << normalisation[i][j][1] << ", px[" << i << "][" << j << "][1] = " << (int)px[1] << endl;	//DEBUG

			int pix2 = (int)((blues[j]-offset)*normalisation[i][j][2]);
			(pix2 < 0) ? (pix2 = 0) : (pix2 = pix2);
			(pix2 > 255) ? (pix2 = 255) : (pix2 = pix2);
			px[2] = pix2;
			// cout << "(" << blues[j] << " - " << offset << ")*" << normalisation[i][j][2] << ", px[" << i << "][" << j << "][2] = " << (int)px[2] << endl;	//DEBUG

		}
	}

	cout << "end of decoding" << endl;

	cout << "writing to PNG file '" << fileName << "'" << endl;
	write_png_file(&fileName[0u]);
	cout << "finished" << endl;
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
    cout << "/ image height: " << imageHeight << endl;
    cout << "| image width: " << imageWidth << endl;
    cout << "\\ offset applied to values: " << (int)(imageContext.plain_modulus().value() - 255) / 2 << endl;
    cout << endl;
}


//###################################################################################################################
//############################################ private classes ######################################################
//###################################################################################################################

void ImagePlaintext::generateKeys()
{
	cout << "generating keys" << endl;

	SEALContext context(imageParameters);

	KeyGenerator generator(context);
    sKey = generator.secret_key();
    pKey = generator.public_key();

    //this key is used during ciphertext values rotation (used during matric filtering)
    //current Galois key is generated with a Decomposition Bit Count of 30
    //this value is purely subjective, and was simply taken as the mean of possible values
    //taking a lower DBC will slow the rotation process, but will lower the noise generated by it
    //inversely, taking a higher value will result in more noise but will process faster
    generator.generate_galois_keys(30, gKey);

    cout << "keys generated successfully" << endl << endl;
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