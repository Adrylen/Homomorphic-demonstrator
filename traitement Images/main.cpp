#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include <seal/seal.h>

using namespace std;
using namespace seal;

#include "image.h"

int main(int argc, char* argv[])
{
	if(argc < 2) abort();

	int schemaFiltre1[9] = 
    {
        0, 1, 0,
        1, -4, 1,
        0, 1, 0
    };
    vector<int> filtreVec1(schemaFiltre1, schemaFiltre1 + sizeof(schemaFiltre1)/sizeof(int));
    Filter edgeDetection("edge detection", 3, 3, filtreVec1);

    int schemaFiltre2[9] = 
    {
        1, 1, 1,
        1, 1, 1,
        1, 1, 1
    };
    vector<int> filtreVec2(schemaFiltre2, schemaFiltre2 + sizeof(schemaFiltre2)/sizeof(int));
    Filter meanBlur("mean blur", 3, 3, filtreVec2);

	int schemaFiltre3[9] = 
    {
        0, -1, 0,
        -1, 5, -1,
        0, -1, 0
    };
    vector<int> filtreVec3(schemaFiltre3, schemaFiltre3 + sizeof(schemaFiltre3)/sizeof(int));
    Filter sharpen("sharpen", 3, 3, filtreVec3);

    int schemaFiltre4[9] = 
    {
        -2, -1, 0,
        -1, 1, 1,
        0, 1, 2
    };
    vector<int> filtreVec4(schemaFiltre4, schemaFiltre4 + sizeof(schemaFiltre4)/sizeof(int));
    Filter emboss("emboss", 3, 3, filtreVec4);


	string polyModulus = "1x^1024 + 1"; 
	auto coeffModulus = coeff_modulus_128(8192);

	/*
		pour N=1024 : 12289, 18433, 40961, 59393, 61441, 65537, 79873, 83969
		pour N=2048 : 12289, 40961, 61441, 65537, 86017
		pour N=4096 : 40961, 65537, 114689
		*/
	int plainModulus = 59393;       //valeur marche pour toutes les puissances de 2 jusqu'à 8192 (poly_modulus)
                                    //attention, réduit significativement le bruit disponible (peut être compensé par un coeff modulus plus grand, mais réduit la sécurité (?))

	EncryptionParameters parameters;

	parameters.set_poly_modulus(polyModulus);
	parameters.set_coeff_modulus(coeffModulus);
	parameters.set_plain_modulus(plainModulus);

	SEALContext context(parameters);

	auto qualifiers = context.qualifiers();
    cout << "Batching enabled: " << boolalpha << qualifiers.enable_batching << endl;
    cout << "poly modulus : " << context.poly_modulus().significant_coeff_count() << endl;


	ImagePlaintext monImage1(parameters, argv[1]);
	cout << "parametres de monImage : ";
	monImage1.printParameters();
	ImageCiphertext imageCryptee1;
	monImage1.encrypt(imageCryptee1);
    imageCryptee1.negate();
    monImage1.decrypt(imageCryptee1);
    monImage1.toImage("imageNegated.png");


    ImagePlaintext monImage2(parameters, argv[1]);
    cout << "parametres de monImage : ";
    monImage2.printParameters();
    ImageCiphertext imageCryptee2;
    monImage2.encrypt(imageCryptee2);
    imageCryptee2.grey();
    monImage2.decrypt(imageCryptee2);
    monImage2.toImage("imageGreyed.png");


    ImagePlaintext monImage3(parameters, argv[1]);
    cout << "parametres de monImage : ";
    monImage3.printParameters();
    ImageCiphertext imageCryptee3;
    monImage3.encrypt(imageCryptee3);
    imageCryptee3.applyFilter(meanBlur, 7);
    monImage3.decrypt(imageCryptee3);
    monImage3.toImage("imageFiltered.png");

 

	return 0;
}
