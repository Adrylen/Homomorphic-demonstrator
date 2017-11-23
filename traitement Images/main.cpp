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

    int dynamiqueValeursPlain = 256;    //peut être modifié si on travaille avec des valeurs comportant une autre dynamique (si on veux inverser des int par exemple)


	string polyModulus = "1x^1024 + 1"; 
	auto coeffModulus = coeff_modulus_128(4096);
	int plainModulus = 40961;       //valeur marche pour toutes les puissances de 2 jusqu'à 8192 (poly_modulus)
                                    //attention, réduit significativement le bruit disponible (peut être compensé par un coeff modulus plus grand, mais réduit la sécurité (?))

	EncryptionParameters parameters;

	parameters.set_poly_modulus(polyModulus);
	parameters.set_coeff_modulus(coeffModulus);
	parameters.set_plain_modulus(plainModulus);

	SEALContext context(parameters);

	auto qualifiers = context.qualifiers();
    cout << "Batching enabled: " << boolalpha << qualifiers.enable_batching << endl;

	ImagePlaintext monImage(context, argv[1]);
	monImage.printParameters();

	ImageCiphertext imageCryptee(monImage);

	imageCryptee.encrypt(monImage);
	ImageCiphertext imageLoaded(imageCryptee);	//créée en tant que copie de l'imageCryptée

	imageCryptee.save("~Ciphertext");
	imageLoaded.load("~Ciphertext");

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

    // imageLoaded.negate();
	// imageLoaded.grey();
	imageLoaded.applyFilter(filtreContours);

	imageLoaded.save("~CiphertextFiltered");

	ImagePlaintext imageFinale = imageLoaded.decrypt();

	imageFinale.toImage("imageResult.png");

	return 0;
}
