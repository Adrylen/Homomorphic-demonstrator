#include <chrono>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include "seal.h"

using namespace std;
using namespace seal;

void benchmark(ofstream&, int, string, BigUInt, int, int);

int main() {

	const vector<string> poly_modulus_list {
		"1x^1024 + 1",
		"1x^2048 + 1",
		"1x^4096 + 1",
		"1x^8192 + 1",
		"1x^16384 + 1",
		"1x^32768 + 1"
	};

	const vector<BigUInt> coeff_modulus_list {
		ChooserEvaluator::default_parameter_options().at(1024),
		ChooserEvaluator::default_parameter_options().at(2048),
		ChooserEvaluator::default_parameter_options().at(4096),
		ChooserEvaluator::default_parameter_options().at(8192),
		ChooserEvaluator::default_parameter_options().at(16384),
		ChooserEvaluator::default_parameter_options().at(32768)
	};

	const vector<int> plain_modulus_list { 1 << 4, 1 << 5, 1 << 6, 1 << 7, 1 << 8 };
	const vector<int> decomposition_bit_count_list { 16, 32, 64, 128, 256 };

	ofstream file;
	file.open("benchmarkResults.txt", ios::app);

	/* Test benchmark Programme */
	cout << "/============================\\" << endl;
	cout << "*  TEST BENCHMARK PROGRAMME  *" << endl;
	cout << "\\============================/" << endl;
	cout << endl;

	benchmark( file, -1,
		poly_modulus_list[0],
		coeff_modulus_list[0],
		plain_modulus_list[0],
		decomposition_bit_count_list[0]
	);
	benchmark( file, -2,
		poly_modulus_list[0],
		coeff_modulus_list[0],
		plain_modulus_list[0],
		decomposition_bit_count_list[1]
	);

	// /* Real benchmark */
	// cout << "/============================\\" << endl;
	// cout << "*  FULL BENCHMARK PROGRAMME  *" << endl;
	// cout << "\\============================/" << endl;
	// cout << endl;

	// int id = 0;
	// for (int i = 0; i < poly_modulus_list.size(); ++i) {
	// 	for (int j = 0; j < plain_modulus_list.size(); ++j) {
	// 		for (int k = 0; k < decomposition_bit_count_list.size(); ++k) {
	// 			benchmark( file, ++id,
	// 				poly_modulus_list[i],
	// 				coeff_modulus_list[i],
	// 				plain_modulus_list[j],
	// 				decomposition_bit_count_list[k]
	// 			);
	// 		}
	// 	}
	// }

	file.close();
	return 0;
}

void benchmark(ofstream& file, int id, string poly_modulus, BigUInt coeff_modulus, int plain_modulus, int decomposition_bit_count) {
	/* Benchmark START */
	file << "============== BENCHMARK N°" << id << " ==============" << endl;
	file << endl;

	/* Write parameters in file */
	file << "Parameters loaded : " << endl;
	file << "{ Poly Modulus            : " << poly_modulus << endl;
	file << "{ Coeff Modulus           : " << coeff_modulus.to_string() << endl;
	file << "{ Plain Modulus           : " << plain_modulus << endl;
	file << "{ Decomposition Bit Count : " << decomposition_bit_count << endl;
	file << endl;

	/* Parameters settings */
	EncryptionParameters parameters;
	parameters.set_poly_modulus(poly_modulus);
	parameters.set_coeff_modulus(coeff_modulus);
	parameters.set_plain_modulus(plain_modulus);
	parameters.set_decomposition_bit_count(decomposition_bit_count);
	parameters.validate();

	/* Key generation */
	KeyGenerator keygen(parameters);
	keygen.generate(1);				// generate 1 evaluation key
	auto secret_key = keygen.secret_key();
	auto public_key = keygen.public_key();
	auto evk = keygen.evaluation_keys();

	/* Encryption tools declaration */
	Encryptor encryptor(parameters, public_key);
	Decryptor decryptor(parameters, secret_key);
	Evaluator evaluator(parameters, evk);
	IntegerEncoder encoder(parameters.plain_modulus());

	/* Time variables */
	chrono::microseconds time_encode_sum(0);
	chrono::microseconds time_encrypt_sum(0);
	chrono::microseconds time_addition_sum(0);
	chrono::microseconds time_multiply_sum(0);
	chrono::microseconds time_square_sum(0);
	chrono::microseconds time_relinearize_sum(0);
	chrono::microseconds time_decrypt_sum(0);
	chrono::microseconds time_decode_sum(0);
	chrono::microseconds time_benchmark(0);

	/* Running of 100 execution package */
	int i = 0;
	int count = 100;
	int fail_sum = 0;
	int fail_prod = 0;
	cout << "Running benchmark n°" << id << " | ";
	do {
		/* Bechmark symbol */
		string symbol = ".";

		/* Benchmark */
		auto time_start = chrono::high_resolution_clock::now();

		auto plain1 = encoder.encode(i);
		auto plain2 = encoder.encode(i + 1);
		auto time_encoded = chrono::high_resolution_clock::now();

		auto enc1 = encryptor.encrypt(plain1);
		auto enc2 = encryptor.encrypt(plain2);
		auto time_encrypted = chrono::high_resolution_clock::now();

		auto enc_sum = evaluator.add(enc1, enc2);
		auto time_addition = chrono::high_resolution_clock::now();
		
		auto enc_prod = evaluator.multiply(enc1, enc2);
		auto time_multiplied = chrono::high_resolution_clock::now();
		
		auto enc_square = evaluator.square(enc1);
		auto time_squared = chrono::high_resolution_clock::now();
		
		auto enc_relin_sum = evaluator.relinearize(enc_sum);
		auto enc_relin_prod = evaluator.relinearize(enc_prod);
		auto time_relinearized = chrono::high_resolution_clock::now();
		
		auto plain_sum = decryptor.decrypt(enc_relin_sum);
		auto plain_prod = decryptor.decrypt(enc_relin_prod);
		auto time_decrypted = chrono::high_resolution_clock::now();
		
		int32_t result_addition = encoder.decode_int32(plain_sum);
		int32_t result_multiplied = encoder.decode_int32(plain_prod);
		auto time_decoded = chrono::high_resolution_clock::now();

		/* Checking results */
		int correct_result_addition = i + (i + 1);
		if (result_addition != correct_result_addition) {
			++fail_sum;
			symbol = "x";
		}
		int correct_result_multiplied = i * (i + 1);
		if (result_multiplied != correct_result_multiplied) {
			++fail_prod;
			symbol = "x";
		}

		/* Progressing */
		cout << symbol;
		cout.flush();

		time_encode_sum			+= chrono::duration_cast<chrono::microseconds>( time_encoded		- time_start		);
		time_encrypt_sum		+= chrono::duration_cast<chrono::microseconds>( time_encrypted		- time_encoded		);
		time_addition_sum		+= chrono::duration_cast<chrono::microseconds>( time_addition		- time_encrypted	);
		time_multiply_sum		+= chrono::duration_cast<chrono::microseconds>( time_multiplied		- time_addition		);
		time_square_sum			+= chrono::duration_cast<chrono::microseconds>( time_squared		- time_multiplied	);
		time_relinearize_sum	+= chrono::duration_cast<chrono::microseconds>( time_relinearized	- time_squared		);
		time_decrypt_sum		+= chrono::duration_cast<chrono::microseconds>( time_decrypted		- time_relinearized	);
		time_decode_sum			+= chrono::duration_cast<chrono::microseconds>( time_decoded		- time_decrypted	);
		time_benchmark			+= chrono::duration_cast<chrono::microseconds>( time_decoded		- time_start		);


	} while (++i < count);

	/* End of process */
	cout << " done." << endl;
	cout.flush();

	/* Write fails */
	file << "Failed to add : " << fail_sum << endl;
	file << "Failed to multiply : " << fail_prod << endl;
	file << endl;

	/* Average calculation */
	auto avg_encode			= time_encode_sum.count()		/ (2 * count);
	auto avg_encrypt		= time_encrypt_sum.count()		/ (2 * count);
	auto avg_addition		= time_addition_sum.count()		/ (1 * count);
	auto avg_multiply		= time_multiply_sum.count()		/ (1 * count);
	auto avg_square			= time_square_sum.count()		/ (1 * count);
	auto avg_relinearize	= time_relinearize_sum.count()	/ (2 * count);
	auto avg_decrypt		= time_decrypt_sum.count()		/ (2 * count);
	auto avg_decode			= time_decode_sum.count()		/ (2 * count);
	auto avg_benchmark		= time_benchmark.count()		/ (1 * count);

	/* Save results in file */
	file << "Average encode :      " << avg_encode		<< " microseconds" << endl;
	file << "Average encrypt :     " << avg_encrypt		<< " microseconds" << endl;
	file << "Average addition :    " << avg_addition	<< " microseconds" << endl;
	file << "Average multiply :    " << avg_multiply	<< " microseconds" << endl;
	file << "Average square :      " << avg_square		<< " microseconds" << endl;
	file << "Average relinearize : " << avg_relinearize	<< " microseconds" << endl;
	file << "Average decrypt :     " << avg_decrypt		<< " microseconds" << endl;
	file << "Average decode :      " << avg_decode		<< " microseconds" << endl;
	file << "Average benchmark :   " << avg_benchmark	<< " microseconds" << endl;
	file << endl;

	/* Benchmark END */
	file << "============================================" << endl;
}
