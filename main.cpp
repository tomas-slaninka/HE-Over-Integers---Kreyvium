#include <NTL/ZZ.h>
#include <NTL/RR.h>
#include <array>
#include <vector>
#include <stdlib.h>
#include <time.h>
#include <algorithm>
#include <chrono>

using namespace std;
using namespace NTL;

// Defining global parameters(settings) of encryption scheme:
// bit-length of the integers in the public key
const long bits_in_pk = 290000;
// bit-length of the secret key
const long bits_in_sk = 988;
// bit-length of the noise
const long bits_in_noise = 26;
// number of integers in the public key
const long integers_in_pk = 188;
// number of integers in subset of public key, that is used for encryption - half of the nb. of integers in pk
const long integers_in_enc_subset = integers_in_pk / 2;


// number of initial rounds in Kreyvium - normally 1152
const long init_rounds = 400;


//
ZZ customModulus(ZZ c, ZZ p) {
	ZZ result;
	RR tmp;
	ZZ tmp_integer;
	RR local_c = MakeRR(c, 0);
	RR local_p = MakeRR(p, 0);
	double a = 0.5;

	tmp = local_c / local_p;
	//cout << tmp << endl;
	tmp_integer = c / p;

	if ((tmp - MakeRR(tmp_integer, 0)) > RR(a))
		tmp_integer += 1;
	//cout << tmp_integer << endl;

	result = c - p * tmp_integer;
	
	return result;
}

// Create subset from the set - set has hald-of-the-key size
vector<int> generate_subset(int subset_size, int set_size) {
	vector<int> set;
	vector<int> subset;
	int posit;

	for (int i = 1; i < set_size; i++)
		set.push_back(i);

	for (int i = 0; i < subset_size; i++) {
		posit = rand() % set.size();
		//cout << endl << "Position: " << posit << endl;
		subset.push_back(set[posit]);
		//cout << "Pushed value: " << set[posit] << endl << endl;
		set.erase(set.begin() + (posit));
	}
	return subset;

}

// encrypt plaintext m using public key pk
ZZ encrypt(ZZ m, array<ZZ, integers_in_pk> pk) {

	ZZ result;
	ZZ r, power_ro;
	vector<int> subset;

	subset = generate_subset(integers_in_enc_subset, integers_in_pk);
	
	result = pk[subset[0]];
	for (int i = 1; i < subset.size(); i++) {
		result = result + pk[subset[i]];
	}
	
	r = RandomBits_ZZ(bits_in_noise);
	if (rand() % 2 == 0)
		r = r * ZZ(-1);
	result = m + 2 * r + 2 * result;

	result = customModulus( result , pk[0] );

	return result;
}

// decrypt ciphertext c using secret key sk
ZZ decrypt(ZZ c, ZZ sk) {
	ZZ result;

	result = customModulus(customModulus(c, sk), ZZ(2));

	return result;
}

template <typename K, typename IV, typename S, typename O, size_t N>
void Kreyvium(std::array<K, 128> const &key, std::array<IV, 128> const &iv,
              std::array<S, 288> &state, std::array<O, N> &output) {

  // copy the key and the iv
  // std::cout << "copy" << std::endl;
  std::array<K, 128> keyp = key;
  std::array<IV, 128> ivp = iv;
  // std::copy(key.begin(), key.end(), keyp.begin());
  // std::copy(iv.begin(), iv.end(), ivp.begin());
  std::reverse(keyp.begin(), keyp.end());
  std::reverse(ivp.begin(), ivp.end());

  // std::cout << "loop" << std::endl;
  for (size_t i = 1; i <= init_rounds + N; i++) {
    // std::cout << "loop " << i << std::endl;
    auto t1 = state[66 - 1] + state[93 - 1];
    // std::cout << "loop " << i << std::endl;
    auto t2 = state[162 - 1] + state[177 - 1];
    // std::cout << "loop " << i << std::endl;
    auto t3 = state[243 - 1] + state[288 - 1] + keyp[0];
    if (i > init_rounds) 
        output[i - init_rounds - 1] = t1 + t2 + t3;
    // std::cout << "loop " << i << std::endl;
    t1 += state[91 - 1] * state[92 - 1] + state[171 - 1] + ivp[0];
    t2 += state[175 - 1] * state[176 - 1] + state[264 - 1];
    t3 += state[286 - 1] * state[287 - 1] + state[69 - 1];
    auto t4 = keyp[0];
    auto t5 = ivp[0];
    // std::cout << "loop " << i << std::endl;
    for (size_t j = 93; j > 1; j--) state[j - 1] = state[j - 2];
    state[1 - 1] = t3;
    for (size_t j = 177; j > 94; j--) state[j - 1] = state[j - 2];
    state[94 - 1] = t1;
    for (size_t j = 288; j > 178; j--) state[j - 1] = state[j - 2];
    state[178 - 1] = t2;
    for (size_t j = 0; j < 127; j++) keyp[j] = keyp[j + 1];
    keyp[127] = t4;
    for (size_t j = 0; j < 127; j++) ivp[j] = ivp[j + 1];
    ivp[127] = t5;
    // std::cout << "loop " << i << std::endl;
  }
}

template <typename K, typename IV, typename S, typename O, size_t N>
void Kreyvium(std::array<K, 128> const &key, std::array<IV, 128> const &iv,
              std::array<S, 288> &state, std::array<O, N> &output, ZZ sk) {

  // copy the key and the iv
  // std::cout << "copy" << std::endl;
  std::array<K, 128> keyp = key;
  std::array<IV, 128> ivp = iv;
  // std::copy(key.begin(), key.end(), keyp.begin());
  // std::copy(iv.begin(), iv.end(), ivp.begin());
  std::reverse(keyp.begin(), keyp.end());
  std::reverse(ivp.begin(), ivp.end());

  // std::cout << "loop" << std::endl;
  for (size_t i = 1; i <= init_rounds + N; i++) {
    // std::cout << "loop " << i << std::endl;
    auto t1 = ( state[66 - 1] + state[93 - 1] ) % sk;
    // std::cout << "loop " << i << std::endl;
    auto t2 = ( state[162 - 1] + state[177 - 1] ) % sk;
    // std::cout << "loop " << i << std::endl;
    auto t3 = ( state[243 - 1] + state[288 - 1] + keyp[0] ) % sk;
    if (i > init_rounds) 
        output[i - init_rounds - 1] = ( t1 + t2 + t3 ) % sk;
    // std::cout << "loop " << i << std::endl;
    t1 += ( state[91 - 1] * state[92 - 1] + state[171 - 1] + ivp[0] ) % sk;
    t2 += ( state[175 - 1] * state[176 - 1] + state[264 - 1] ) % sk;
    t3 += ( state[286 - 1] * state[287 - 1] + state[69 - 1] ) % sk;
    auto t4 = keyp[0];
    auto t5 = ivp[0];
    // std::cout << "loop " << i << std::endl;
    for (size_t j = 93; j > 1; j--) state[j - 1] = ( state[j - 2] ) % sk;
    state[1 - 1] = t3;
    for (size_t j = 177; j > 94; j--) state[j - 1] = ( state[j - 2] ) % sk;
    state[94 - 1] = t1;
    for (size_t j = 288; j > 178; j--) state[j - 1] = ( state[j - 2] ) % sk;
    state[178 - 1] = t2;
    for (size_t j = 0; j < 127; j++) keyp[j] = keyp[j + 1];
    keyp[127] = t4;
    for (size_t j = 0; j < 127; j++) ivp[j] = ivp[j + 1];
    ivp[127] = t5;
    // std::cout << "loop " << i << std::endl;
  }
}

int main()
{
	ZZ sk;
	ZZ q, r;
	int posit;
	array<ZZ, integers_in_pk> pk;
    // Timer
    auto start = std::chrono::steady_clock::now();
    auto end = std::chrono::steady_clock::now();
    std::chrono::duration<double> elapsed_seconds;
    size_t const N = 30;

	RR::SetPrecision(10*bits_in_pk);
	
	srand(time(NULL));

	// generete odd number as secret key
	do {
		RandomLen(sk, bits_in_sk);
	} while ((sk % ZZ(2)) == ZZ(0));

	ZZ upperBound = power2_ZZ(bits_in_pk);	
	ZZ upperBound_divided_p = upperBound/sk;
	// generate whole public key
	do {
		// x_i = sk * q_i + r_i
		for (int i = 0; i < integers_in_pk; i++) {
			/*
			RandomLen(q, bits_in_pk);
			q = q / sk;*/
			RandomBnd(q, upperBound_divided_p);
			//cout << "q = " << q << endl;

			r = RandomBits_ZZ(bits_in_noise);
			if (rand() % 2 == 0)
				r = r * ZZ(-1);
			//cout << "r = " << r << endl;
			pk[i] = sk * q + r;

			if (i == 0)
				posit = 0;
			else if (pk[i] > pk[posit])
				posit = i;

		}
		ZZ tmp = pk[0];
		pk[0] = pk[posit];
		pk[posit] = tmp;

		// pk[0] musi byt parne + pk[0] % sk musi byt neparne
	} while ((!IsOdd(pk[0])) || ( IsOdd(customModulus(pk[0],sk))));

	/*array<ZZ, 80> test_vector;
	array<ZZ, 80> test_vector_result;
	ZZ enc_text;
	ZZ dec_text;
    ZZ add_one = ZZ(1);
    ZZ add_one_enc;
    ZZ multiply_one = ZZ(1);
    ZZ multiply_one_enc;
	int same = 0;
	int different = 0;

	//cout << endl << "Plain text:" << endl;
	for (int i = 0; i < 80; i++) {
		test_vector[i] = RandomBits_ZZ(1);
		cout << test_vector[i];
	}

	add_one_enc = encrypt(add_one, pk);

	//cout << endl << "Deciphered text: " << endl;
	for (int i = 0; i < 80; i++) {
		enc_text = encrypt(test_vector[i], pk);

        enc_text = enc_text + add_one_enc;
        enc_text %= sk;

        enc_text = enc_text + add_one_enc;
        enc_text %= sk;

		test_vector_result[i] = decrypt(enc_text, sk);
		cout << test_vector_result[i];
		if (test_vector[i] != test_vector_result[i])
			different += 1;
		else
			same += 1;
	}
	
	cout << endl << "Same:" << same;
	cout << endl << "Different:" << different;

    return 0;*/

    // Seed (for deterministic values)
  srand(0);

  // Key & IV
  std::array<unsigned long, 128> key, iv;
  std::generate(key.begin(), key.end(), [] { return rand() & 1; });
  std::generate(iv.begin(), iv.end(), [] { return rand() & 1; });

  // State and output
  std::array<unsigned long, 288> state;
  std::array<unsigned long, N> output;

  for (size_t i = 1; i < 94; i++) state[i - 1] = key[i - 1];
  for (size_t i = 94; i < 178; i++) state[i - 1] = iv[i - 94];
  for (size_t i = 84; i < 128; i++) state[i + 94 - 1] = iv[i];
  for (size_t i = 222; i < 288; i++) state[i - 1] = 1;
  state[288 - 1] = 0;

  // Plaintext krevium
  start = std::chrono::steady_clock::now();
  Kreyvium(key, iv, state, output);
  end = std::chrono::steady_clock::now();
    
  elapsed_seconds = end - start;
  std::cout << "\tPlaintext Kreyvium: \t\t"
            << elapsed_seconds.count() << " s" << std::endl;

  // Print output
  for (auto const &v : output) {
    std::cout << v % 2;
  }
  std::cout << std::endl;

  //return 0;

  // Encrypted Key
  std::array<ZZ, 128> e_key;
  std::array<ZZ, 128> e_iv;
  start = std::chrono::steady_clock::now();
  for (size_t i = 0; i < 128; i++)
    e_key[i] = encrypt(ZZ(key[i]), pk);
  for (size_t i = 0; i < 128; i++)
    e_iv[i] = encrypt(ZZ(iv[i]), pk);
  end = std::chrono::steady_clock::now();
  elapsed_seconds = end - start;
  std::cout << "\tEncrypt Key: \t\t" << elapsed_seconds.count()
            << " us" << std::endl;

  // Encrypted state & output
  std::array<ZZ, 288> e_state;
  std::array<ZZ, N> e_output;

  for (size_t i = 1; i < 94; i++) e_state[i - 1] = e_key[i - 1];
  for (size_t i = 94; i < 178; i++) e_state[i - 1] = e_iv[i - 94];
  for (size_t i = 84; i < 128; i++) e_state[i + 94 - 1] = e_iv[i];
  for (size_t i = 222; i < 288; i++) e_state[i - 1] = encrypt(ZZ(1), pk);
  e_state[288 - 1] = encrypt(ZZ(0), pk);

  // Kreyvium
  start = std::chrono::steady_clock::now();
  Kreyvium(e_key, e_iv, e_state, e_output, sk);
  end = std::chrono::steady_clock::now();
  elapsed_seconds = end - start;
  std::cout << "\tHomomorphic Kreyvium: \t\t"
            << elapsed_seconds.count() << " s"
            << std::endl;

 for (auto const &v : e_output) {
    cout << decrypt(v, sk);
  }
  std::cout << std::endl;

return 0;

}
