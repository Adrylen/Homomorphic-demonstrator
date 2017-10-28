#include <chrono>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include "seal.h"

using namespace std;
using namespace seal;

int main()
{

	string polyModulus = "1x^1024 + 1";
    
	BigUInt coeffModulus = ChooserEvaluator::default_parameter_options().at(1024);

	int plainModulus = 65537;       //valeur marche pour toutes les puissances de 2 jusqu'à 8192 (poly_modulus)
                                    //attention, réduit significativement le bruit disponible (peut être compensé par un coeff modulus plus grand, mais réduit la sécurité (?))

    int dynamiqueValeursPlain = 256;    //peut être modifié si on travaille avec des valeurs comportant une autre dynamique (si on veux inverser des int par exemple)

	EncryptionParameters parameters;

	parameters.set_poly_modulus(polyModulus);
	parameters.set_coeff_modulus(coeffModulus);
	parameters.set_plain_modulus(plainModulus);

	parameters.validate();


	PolyCRTBuilder crtbuilder(parameters);

	vector<BigUInt> values(crtbuilder.get_slot_count(), BigUInt(parameters.plain_modulus().bit_count(), static_cast<uint64_t>(0)));
    vector<BigUInt> reducteur(crtbuilder.get_slot_count(), BigUInt(parameters.plain_modulus().bit_count(), static_cast<uint64_t>(plainModulus - dynamiqueValeursPlain + 1)));

    for(int i=0; i<128; i++)
    {
        values[i] = i*2;
    }

	cout << "Plaintext slot contents (slot, value): ";
    for (size_t i = 0; i < 128; ++i)
    {
        cout << "(" << i << ", " << values[i].to_dec_string() << ")" << ((i != 127) ? ", " : "\n");
    }

    Plaintext plainPoly = crtbuilder.compose(values);
    Plaintext reduction = crtbuilder.compose(reducteur);

    KeyGenerator generator(parameters);
    generator.generate();
    Plaintext secretKey = generator.secret_key();
    Ciphertext publicKey = generator.public_key();

    Encryptor encryptor(parameters, publicKey);
    Evaluator evaluator(parameters);
    Decryptor decryptor(parameters, secretKey);

    Ciphertext encryptedPoly = encryptor.encrypt(plainPoly);
    cout << "Noise budget at start: " << decryptor.invariant_noise_budget(encryptedPoly) << " bits" << endl;

    Ciphertext modifiedPoly = evaluator.negate(encryptedPoly);

    Ciphertext reductedPoly = evaluator.sub_plain(modifiedPoly, reduction);
    cout << "Noise budget in result: " << decryptor.invariant_noise_budget(reductedPoly) << " bits" << endl;

    Plaintext finalPoly = decryptor.decrypt(reductedPoly);


    crtbuilder.decompose(finalPoly, values);

    cout << "negated contents (slot, value): ";
    for (size_t i = 0; i < 128; ++i)
    {
        cout << "(" << i << ", " << values[i].to_dec_string() << ")" << ((i != 127) ? ", " : "\n");
    }
}
