#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <chrono>
#include <png.h>


#include <seal/seal.h>
#include "filter.h"


using namespace std;
using namespace seal;


class ImageCiphertext;
class ImagePlaintext;

class ImageCiphertext
{

	public :

		/**
		 * @brief empty contructor for ImageCiphertext, only creates an instance without initialisation
		 * @details this contructor is intended to create an instance of the class ImageCiphertext, 
		 * this class holds the encrypted data of the image, with additional parameters, 
		 * such as a normalisation matrix (needed to divide values once multiplications are done to data)
		 */
		ImageCiphertext(){};

		/**
		 * @brief copy constructor
		 * @details creates a strict copy of ImageCiphertext autre
		 * every parameter is copied to the new ImageCiphertext
		 * 
		 * @param autre reference to ImageCiphertext to copy
		 */
		ImageCiphertext(ImageCiphertext& autre);
		
		/**
		 * @brief ImageCiphertext assignment
		 * @details copies the content of the rvalue ImageCiphertext to the lvalue ImageCiphertext 
		 * every parameter is copied from one instance to the other
		 * 
		 * @param assign lvalue ImageCiphertext
		 */
		ImageCiphertext& operator=(const ImageCiphertext& assign);

		/**
		 * @brief creates an ImageCiphertext with given parameters
		 * @details creates an ImageCiphertext and assign to it given parameters
		 * this constructor is called by ImagePlaintext when encrypting data
		 * 
		 * @param parameters encryption parameters of the ciphertexts contained in data
		 * @param height height of the image contained
		 * @param width width of the image contained
		 * @param pKey public key of the ciphertexts in data
		 * @param gKey galois key corresponding to ciphertexts (this key is needed for rotations)
		 * @param encryptedData vector containing encrypted lines of the image
		 */
		ImageCiphertext(EncryptionParameters parameters, int height, int width, PublicKey pKey, GaloisKeys gKey, vector<Ciphertext> encryptedData);

		/**
		 * @brief method to negate the image
		 * @details this method inverts pixel values of the image contained in the encrypted data
		 * it can only be called if no other operation has been made to the data
		 */
		void negate();

		/**
		 * @brief method to convert image to greyscale
		 * @details this method converts pixels values to greyscale, applying a percentage to calculate common value
		 * the percentages taken are 21% red, 72% green and 7% blue
		 */
		void grey();

		/**
		 * @brief this method applies a convolution matrix to every pixel of the image
		 * @details this method takes a Filter taken as argument to execute the convolution matrix to the image
		 * this function is slow, but supports multithreading (if no value is given for multithreading, default value will be one thread)
		 * for user's comfort, the percentage of completion of each thread is printed to stdout
		 * 
		 * @param filter Class containing it's height, width (both must be odd) and values for each position
		 * @param numThread number of threads to lauch for calculations, will make sure values entered are coherent, default value is 1
		 */
		void applyFilter(Filter filter, int numThread = 1);

		/**
		 * @brief saves data and parameters to a binary file
		 * @details saves every parameter and data of the image to a binary file. 
		 * Be careful though, as the weight of such a file can be quite large (more than 10 MB)
		 * 
		 * @param fileName the name to give the file
		 */
		void save(string fileName);

		/**
		 * @brief loads the parameters and data from an existing file
		 * @details loads all data and parameters previously saved from the 'save' method
		 * 
		 * @param fileName the name of the file to load
		 */
		void load(string fileName);

		/**
		 * @brief returns the number of ciphertexts in encrypted data
		 * @details returns the size of the vector containing the ciphertexts of the lines of the image
		 * 
		 * @return an unsigned int
		 */
		uint32_t getDataSize()
		{
			return encryptedImageData.size();
		}

		/**
		 * @brief returns the ciphertext at index given
		 * @details returns the ciphertext contained in data at position 'index' if it exists, throw an out_of_range error otherwise
		 * remember data is stored as red line, green line, blue line, red line, green line...
		 * 
		 * @param index position of the ciphertext to get
		 * @return a Ciphertext containing values of one color of a line of the image
		 */
		Ciphertext getDataAt(uint32_t index)
		{
			if(index >= encryptedImageData.size())
				throw std::out_of_range("index must be less than data size");
			return encryptedImageData.at(index);
		}

		/**
		 * @brief returns the vector containing all the encrypted data of the image
		 * @details returns the reference of the vector to the encrypted data of the image
		 * @return a vector of Ciphertext
		 */
		vector<Ciphertext> getAllData()
		{
			return encryptedImageData;
		}

		/**
		 * @brief returns the height of the image in pixels
		 * @details returns the value of the parameter imageHeight contained in the instance
		 * @return an unsigned int 
		 */
		uint32_t getHeight()
		{
			return imageHeight;
		}

		/**
		 * @brief returns the width of the image in pixels
		 * @details returns the value of the parameter imageWidth contained in the instance
		 * @return an unsigned int
		 */
		uint32_t getWidth()
		{
			return imageWidth;
		}

		/**
		 * @brief returns the encryption parameters of the encryption used for the encrypted data
		 * @details returns the encryption parameters contained in the instance
		 * those parameters are used to create a SEALContext (see SEAL documentation)
		 * @return an EncryptionParameters instance (see SEAL Documentation)
		 */
		EncryptionParameters getParameters()
		{
			return imageParameters;
		}

		/**
		 * @brief returns the public key corresponding to the encrypted data
		 * @details returns the public key contained in the instance
		 * this key is used to encrypt data, but the secret key must be used to decrypt
		 * @return a PublicKey instance (see SEAL documentation)
		 */
		PublicKey getPublicKey()
		{
			return pKey;
		}

		/**
		 * @brief returns the galois key corresponding to the encrypted data
		 * @details returns the galois key contained in the instance
		 * this key is meant to be used for value rotations in Ciphertexts
		 * if poly_modulus is X^N + 1, then ciphertexts are represented as matrices of 2 lines and N/2 columns : 
		 * [[0, 1, 2, ..., 511], [512, 513, ..., 1023]] for N = 1024
		 * this key is used to swap lines and rotate columns (see SEAL documentation)
		 * @return a GaloisKey instance (see SEAL documentation)
		 */
		GaloisKeys getGaloisKeys()
		{
			return gKey;
		}

		/**
		 * @brief returns the reference pointing to the first value of the normalisation matrix
		 * @details returns a pointer to the normalisation table
		 * this table is a 3-dimensional matrix keeping history of multiplications for each pixel
		 * when decoding, the values recovered are multiplied by the corresponding values in normalisation to get the pixel values
		 * @return a triple pointer to float
		 */
		float*** getNorm()
		{
			return normalisation;
		}

		/**
		 * @brief prints the parameters of data and image
		 * @details prints to stdout the encryption parameters, as well as the image height, width and the offset applied to values while encoding
		 */
		void printParameters();

		/**
		 * @brief method for demonstration, creates an image with same dimensions and tries to decrypt data in it
		 * @details this method decrypts the encrypted data contained with a wrong secret key created at construction 
		 * then decode decrypted data to write it in a PNG file by calling write_png_file
		 * good to know : alpha value is set manually for each pixel to 255 (no transparency)
		 * 
		 * @param fileName the name of the resulting PNG file
		 */
		void wrongDecryption(string fileName);

	private :
		/**
		 * @brief adds the values from index 'min' to index 'max' to index position in a Ciphertext
		 * @details uses Ciphertext rotation to get every value in a range around a specific position in ciphertext added to this position
		 * this method is used to get multiplied values of pixels in a line to a single pixel position
		 * 
		 * @param imageContext the context created from the encryption parameters kept by the instance
		 * @param cipher the ciphertext (corresponding to a color of a line of the image)
		 * @param position the position where values around have to be added
		 * @param min the position of the first value to take
		 * @param max the position of the last value to take
		 * @param pool pool used and generated by applyFilter, used to manage more efficiently multi-threading
		 * @return returns a Ciphertext containing the new value at index 'position' and old values everywhere else
		 */
		Ciphertext addColumns(SEALContext imageContext, Ciphertext cipher, int position, int min, int max, const MemoryPoolHandle &pool);

		/**
		 * @brief uses the convolution matrix contained in filter to execute the convolution at the pixel in position (x, y), in a specific color layer
		 * @details executes the convolution using the matrix contained in filter on the given pixel in coordinates x, y on color layer
		 * if the convolution has to take pixels outside of the image, the algorithm takes the closest value (extension technique)
		 * this method takes a SEAL pool to make the calculations, as it can be threaded
		 * the ciphertext returned contains zeros, except at the y position given, where it contains the value 
		 * resulting from the sum of all surrounding values multiplied by the convolution matrix' values
		 * 
		 * @param context the context created from the encryption parameters 
		 * @param x the height position of the pixel value to evaluate
		 * @param y the width position of the pixel to evaluate
		 * @param colorLayer the color layer of the pixel to evaluate
		 * @param filter the filter to execute on the pixel
		 * @param rmtx the read mutex used to prevent data corruption during readings of data
		 * @param pool the SEAL pool used for convolution (see SEAL documentation)
		 * @return return a Ciphertext instance
		 */
		Ciphertext convolute(SEALContext context, int x, int y, int colorLayer, Filter filter, mutex &rmtx, const MemoryPoolHandle &pool);

		/**
		 * @brief initializes every value of the 'normalisation' matrix
		 * @details initializes every value of the 3-Dimensional matrix 'normalisation' to 1
		 */
		void initNorm();

		/**
		 * @brief updates every value of 'normalisation' by the value given in parameter
		 * @details multiply each value of the 'normalisation' matrix with the given value
		 * thus, the new value is the old one, multiplied by the given one
		 * 
		 * @param value a float with which multiply every value of 'normalisation'
		 */
		void updateNorm(float value);

		/**
		 * @brief verify if every value of 'normalisation' is over the value given
		 * @details checks if every value of the 'normalisation' matrix is over or equal to the value given
		 * 
		 * @param value the value with which compare every one from 'nomrmalisation'
		 * @return returns true if every value is indeed over of equal to the given value, false otherwise
		 */
		bool verifyNormOver(float value);

		void write_png_file(char *filename);

		EncryptionParameters imageParameters;
		PublicKey pKey;
		GaloisKeys gKey;
		SecretKey wrongSKey;	//this key is for demonstration only, doesn't represent the real secret key of the encrypted data
		vector<Ciphertext> encryptedImageData;
		float ***normalisation;

		uint32_t imageHeight, imageWidth;
		png_bytep *row_pointers;	//used to write PNG pictures
};

class ImagePlaintext
{

	public :

		/**
		 * @brief constructor to make an empty instance of ImagePlaintext
		 * @details constructor to make an emty instance of ImagePlaintext
		 * this constructor doesn't initialize any parameter
		 */
		ImagePlaintext(){};

		/**
		 * @brief creates a new instance of ImagePlaintext and initialize parameters and data 
		 * @details creates a new ImagePlaintext and initialize encryption parameters as the ones given
		 * then, reads and encode the image represented by its name given in parameter
		 * finally, generate the keys needed and initialize the normalisation matrix
		 * 
		 * @param parameters encryption parameters to use during all encryption/calculus/decryption process
		 * @param fileName the file name of the image to read (image must be PNG)
		 */
		ImagePlaintext(const EncryptionParameters &parameters, char* fileName);

		/**
		 * @brief creates a new ImagePlaintext with specific encryption parameters and secret key
		 * @details this constructor creates a new ImagePlaintext, stores the encryption parameters and secret key given
		 * 
		 * @param parameters encryption parameters to use
		 * @param sKey secret key to use
		 */
		ImagePlaintext(const EncryptionParameters &parameters, SecretKey sKey);

		/**
		 * @brief encrypts the data contained in the ImagePlaintext, and gives the encrypted data and parameters to the given ImageCiphertext
		 * @details this method encrypts every Plaintext contained in data, then creates a new ImageCiphertext with same parameters 
		 * (encryption parameters, image heigth, width, public key, galois key) and all encrypted data
		 * also prints available noise budget
		 * 
		 * @param destination the ImageCiphertext to be given the encrypted data, it can be uninitialized, as all parameters will be given by this method
		 */
		void encrypt(ImageCiphertext &destination);

		/**
		 * @brief decrypts all data from the ImageCiphertext to store the resulting Plaintexts in its data
		 * @details takes image height, width and normalisation matrix, then decrypts every Ciphertext contained in ImageCiphertext data
		 * every Plaintext obtained is stored in order to its data
		 * 
		 * @param source ImageCiphertext to take encrypted data from
		 */
		void decrypt(ImageCiphertext &source);

		/**
		 * @brief reads a PNG image to get data 
		 * @details every value of every color of every pixel is taken to be put into a coefficient of a SEAL Plaintext 
		 * this plaintext is a polynomial with a certain number of coefficients, represented by the poly_modulus
		 * for encoding and simplicity, the poly_modulus must be larger than the image width, to be able to put every value of a color line into a plaintext
		 * for calculation purposes, an offset is added to the values to put them at the center of the plain_modulus of the coefficients (see SEAL documentation)
		 * every Plaintext created is then added to a vector containing all of the data
		 * the data is thus represented of plaintexts containing values of a specific color for every pixels of a line, with the order of the colors being red, green and blue
		 * 
		 * @param fileName the name of the image file to read
		 */
		void toPlaintext(char* fileName);

		/**
		 * @brief creates a new image from the data containted in the instance
		 * @details decodes every Plaintext contained in the instance data, then removes the offset and applies the normalisation to the value
		 * and finally writes the values to the corresponding image's pixels
		 * 
		 * @param fileName name of the image to create (or replace) 
		 */
		void toImage(string fileName);

		/**
		 * @brief returns the size of the data contained in the instance
		 * @details returns the number of lines contained in the instance
		 * this number corresponds to three times the number of lines in the image, as a Plaintext contains color values red, green or blue of a line
		 * 
		 * @return an unsigned int representing the number of Plaintext
		 */
		uint32_t getDataSize()
		{
			return imageData.size();
		}


		/**
		 * @brief returns the Plaintext at given index
		 * @details returns the Plaintext at given index if exists, throw an out_of_range error otherwise
		 * the general way to get a line is : lineOfImage*3 + colorLayer
		 * 
		 * @param index the index of the Plaintext needed
		 * @return a Plaintext instance
		 */
		Plaintext getDataAt(uint32_t index)
		{
			if(index >= imageData.size())
				throw std::out_of_range("index must be less than data size");
			return imageData.at(index);
		}

		/**
		 * @brief returns the height of the image 
		 * @details returns the height of the image represented by its data in the ImagePlaintext
		 * 
		 * @return an unsigned int
		 */
		uint32_t getHeight()
		{
			return imageHeight;
		}

		/**
		 * @brief returns the width of the image
		 * @details returns the width of the image represented by its data in ImagePlaintext
		 * 
		 * @return an unsigned int
		 */
		uint32_t getWidth()
		{
			return imageWidth;
		}

		/**
		 * @brief returns the encryption parameters of the image data
		 * @details returns the encryption parameters given to the instance when created or after decrypting data from an ImageCiphertext
		 * @return return an EncryptionParameters instance (see SEAL documentation)
		 */
		EncryptionParameters getParameters()
		{
			return imageParameters;
		}

		/**
		 * @brief prints the parameters of data and image
		 * @details prints to stdout the encryption parameters, as well as the image height, width and the offset applied to values while encoding
		 */
		void printParameters();

	private : 
		/**
		 * @brief generates keys from encryption parameters for data encryption/calculus/decryption
		 * @details generates a public key, a secret key and a galois key
		 * the role of the public key is to encrypt data
		 * the role of the secret key is to decrypt data
		 * the role of the galois key is to perform rotations in ciphertexts (see ImageCiphertext's addColumns method)
		 * the galois key is generated with a median Decomposition Bit Count, allowing a trade-off between speed and noise production 
		 */
		void generateKeys();

		void initNorm();

		/**
		 * @brief copy values of another normalisation matrix to the one owned by the instance
		 * 
		 * @param norm the triple pointer to float representing the 3-Dimensional matrix 
		 */
		void copyNorm(float ***norm);

		void read_png_file(char *filename);

		void write_png_file(char *filename);

		EncryptionParameters imageParameters;
		SecretKey sKey;
		PublicKey pKey;
		GaloisKeys gKey;
		vector<Plaintext> imageData;
		float ***normalisation;

		uint32_t imageHeight, imageWidth;
		png_byte color_type;
		png_byte bit_depth;
		png_bytep *row_pointers;
};