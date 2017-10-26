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

	string polyModulus = "1x^128 + 1";

	BigUInt coeffModulus = ChooserEvaluator::default_parameter_options().at(1024);

	int plainModulus = 257;

	EncryptionParameters parameters;

	parameters.set_poly_modulus(polyModulus);
	parameters.set_coeff_modulus(coeffModulus);
	parameters.set_plain_modulus(plainModulus);

	parameters.validate();


	PolyCRTBuilder crtbuilder(parameters);

	vector<BigUInt> values(crtbuilder.get_slot_count(), BigUInt(parameters.plain_modulus().bit_count(), static_cast<uint64_t>(0)));
    vector<BigUInt> padder(crtbuilder.get_slot_count(), BigUInt(parameters.plain_modulus().bit_count(), static_cast<uint64_t>((plainModulus - 255 - 1))));

	values[0] = 0;
	values[1] = 13;
	values[2] = 46;
	values[3] = 157;
	values[4] = 248;
	values[5] = 255;

	cout << "Plaintext slot contents (slot, value): ";
    for (size_t i = 0; i < 6; ++i)
    {
        cout << "(" << i << ", " << values[i].to_dec_string() << ")" << ((i != 5) ? ", " : "\n");
    }

    Plaintext plainPoly = crtbuilder.compose(values);
    Plaintext padding = crtbuilder.compose(padder);

    KeyGenerator generator(parameters);
    generator.generate();
    Plaintext secretKey = generator.secret_key();
    Ciphertext publicKey = generator.public_key();

    Encryptor encryptor(parameters, publicKey);
    Evaluator evaluator(parameters);
    Decryptor decryptor(parameters, secretKey);

    Ciphertext encryptedPoly = encryptor.encrypt(plainPoly);

    Ciphertext paddedPoly = evaluator.add_plain(encryptedPoly, padding);
    
    Ciphertext modifiedPoly = evaluator.negate(paddedPoly);

    Ciphertext unpaddedPoly = evaluator.sub_plain(modifiedPoly, padding);

    Plaintext finalPoly = decryptor.decrypt(unpaddedPoly);


    crtbuilder.decompose(finalPoly, values);

    cout << "negated contents (slot, value): ";
    for (size_t i = 0; i < 6; ++i)
    {
        cout << "(" << i << ", " << values[i].to_dec_string() << ")" << ((i != 5) ? ", " : "\n");
    }
}
