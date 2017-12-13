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
    Filter filtreContours(3, 3, filtreVec1);

    int schemaFiltre2[9] = 
    {
        1, 1, 1,
        1, 1, 1,
        1, 1, 1
    };
    vector<int> filtreVec2(schemaFiltre2, schemaFiltre2 + sizeof(schemaFiltre2)/sizeof(int));
    Filter filtreFlou(3, 3, filtreVec2);


	string polyModulus = "1x^1024 + 1"; 
	auto coeffModulus = coeff_modulus_128(8192);

	/*
		pour N=1024 : 12289, 18433, 40961, 59393, 61441, 65537, 79873, 83969
		pour N=2048 : 12289, 40961, 61441, 65537, 86017
		pour N=4096 : 40961, 65537, 114689
		*/
	int plainModulus = 40961;       //valeur marche pour toutes les puissances de 2 jusqu'à 8192 (poly_modulus)
                                    //attention, réduit significativement le bruit disponible (peut être compensé par un coeff modulus plus grand, mais réduit la sécurité (?))

	EncryptionParameters parameters;

	parameters.set_poly_modulus(polyModulus);
	parameters.set_coeff_modulus(coeffModulus);
	parameters.set_plain_modulus(plainModulus);

	SEALContext context(parameters);

	auto qualifiers = context.qualifiers();
    cout << "Batching enabled: " << boolalpha << qualifiers.enable_batching << endl;
    cout << "poly modulus : " << context.poly_modulus().significant_coeff_count() << endl;

	ImagePlaintext monImage(parameters, argv[1]);
	cout << "parametres de monImage : ";
	monImage.printParameters();

	ImageCiphertext imageCryptee;
	monImage.encrypt(imageCryptee);

    // imageCryptee.negate();
	// imageCryptee.grey();
	imageCryptee.applyFilter(filtreFlou, 8);

	// imageLoaded.save("~CiphertextFiltered");

	monImage.decrypt(imageCryptee);
	monImage.toImage("imageResult.png");

	return 0;
}
