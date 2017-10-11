#include "stdafx.h"

// g++ -g3 -ggdb -O0 -DDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread
// g++ -g -O2 -DNDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread
#include <cstdio>

//included to allow use of sscanf_s instead of sscanf, a deprecated function
#include <stdio.h>

#include <iostream>
#include <osrng.h>
using CryptoPP::AutoSeededRandomPool;

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include <cstdlib>
using std::exit;

#include <cryptlib.h>
using CryptoPP::Exception;

#include <hex.h>
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include <filters.h>
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;

#include <des.h>
using CryptoPP::DES_EDE2;

#include <modes.h>
using CryptoPP::CBC_Mode;

#include <secblock.h>
using CryptoPP::SecByteBlock;
#include <iostream>
#include <string>
#include <modes.h>
#include <aes.h>
#include <filters.h>
/*
CryptoPP::SecByteBlock HexDecodeString(const char *hex)
{
CryptoPP::StringSource ss(hex, true, new CryptoPP::HexDecoder);
CryptoPP::SecByteBlock result((size_t)ss.MaxRetrievable());
ss.Get(result, result.size());
return result;
}*/
#include <Integer.h>
#include <modarith.h>
#include <eccrypto.h>
#include <aes.h>
#include <bitset>
using namespace std;
using namespace CryptoPP;

#include "ECC_point.h"
#include "Chameleon.h"
#include "IBEhelpers.h"

#include <random>


void swap(Integer *a, Integer *b) {
	Integer tmp = *a;
	*a = *b;
	*b = tmp;
}

int main() {
	extern const ECC_point g;
	extern const Integer l;
	extern const Integer d;
	extern const Integer m;
	extern AutoSeededRandomPool rng;

	/*
	Label la(5, "00000", "11111");
	string b0 = la.B0();
	string b1 = la.B1();
	cout << b0 << endl;
	cout << b1 << endl;
	
	la.set(0, 0, 1);
	cout << la.B0() << endl;
	la.set(0, la.B1());
	cout << la.B0() << endl;
	
	for (int i = 0; i < la.size(); i++){
		cout << i << ", 0 : " << la.getLabel(i,0) << ", "  << la.getLstr(i, 0) << ", " << b0[i] << endl;
		cout << i << ", 1 : " << la.getLabel(i,1) << ", " << la.getLstr(i, 1) << ", " << b1[i] << endl;
	}
	*/
	/*
	string s = "11111111111111110000000000000000";
	string v = "0";
	seed_seq seq(s.begin(), s.end());
	minstd_rand0 a(seq);
	
	cout << PRF(s, v) << endl;
	cout << PRF(s, v) << endl;
	cout << PRF(s, v) << endl;
	cout << PRF(s, v) << endl;
	*/
	//testT(3, "helloall!!a", true);
	/*
	Keys k = Keys();
	Traps t = Traps();
	Gen(4, k, t);
	ChameleonCipherText ct;
	string x = "1010";
	int b = 1;
	int index = 2;
	Integer r(rng, 0, m - 1);
	ECC_point h = Hash(k, x, r);
	h.affRepr();
	string hStr = integer_to_bin(h.getX(), 256) + integer_to_bin(h.getY(), 256);
	string message = "helloAll!!";
	helperP(k, hStr, index, b, message, ct, true);
	string decrypted = Dec(k, x, r, ct, true);
	cout << "decrypted: " << decrypted << endl;
	*/
	Keys k;
	Traps t;
	Gen(4,k,t);
	testP(k, true);
	
	//cout << "testing GED\n";
	//testGED(10, "hi", true);
	

	/*
	pair<Keys*, Traps*> kt = Gen(2);
	Keys *k = kt.first;
	string x = "00";
	Integer r(rng, 0, m - 1);
	ECC_point h = Hash(k,x,r);
	ChameleonCipherText* ct = Enc(k, h, 1, 0, "0",true);
	string decrypted = Dec(k, x, r, ct,true);
	cout << decrypted << endl;
	*/
	//cout << int(',') << ", " << int('<') << ", ";
	
	/*
	cout << rand << endl;
	string randStr = integer_to_bin(rand, 256);
	cout << randStr << endl;
	Integer result = bin_to_integer(randStr);
	cout << result << endl;
	*/
	
	/*
	// Generate a random key
	SecByteBlock key(0x00, 32);
	rng.GenerateBlock(key, key.size());

	// Generate a random IV
	SecByteBlock iv(32);
	rng.GenerateBlock(iv, 32);

	char plainText[] = "Hello! How are you.";
	int messageLen = (int)strlen(plainText) + 1;

	string keyStr((char*)(byte*)key.data(), key.size());
	cout << "Key:\n" << keyStr << endl;
	cout << "Key size:\n" << key.size() << endl;
	string ivStr((char*)(byte*)iv.data(),iv.size());
	cout << "Initialization Vector:\n" << ivStr << endl;

	// Encrypt

	CFB_Mode<AES>::Encryption cfbEncryption(key, key.size(), key);
	cfbEncryption.ProcessData((byte*)plainText, (byte*)plainText, messageLen);

	cout << "Encrypted:\n" << plainText << endl;

	// Decrypt

	CFB_Mode<AES>::Decryption cfbDecryption(key, key.size(), key);
	cfbDecryption.ProcessData((byte*)plainText, (byte*)plainText, messageLen);

	cout << "Decrypted:\n" << plainText << endl;
	*/
	/*
	cout << "Generating Keys and Trapdoors\n";
	Keys k;
	Traps t;
	Gen(4, k, t, true);

	cout << "Testing Hash, HashInv\n";
	testHash(k, t, 10);

	cout << "Testing Enc,Dec\n";
	testEncDec(k, t, 10);
	*/
	
	/*
	//Integer intkey(rng, 0, l);
	SecByteBlock key(32);
	//std::bitset<256> key(l);
	//l.Encode(key, 32);

	ostringstream oss;
	for (int i = 255; i >= 0; i--)
		oss << l.GetBit(i);
	
	cout << l << endl;
	cout << key << endl;
	cout << oss.str() << endl; 
	//CFB_Mode<AES>::Encryption a(key, 32);
	*/



	//test_proj_aff_add_double(10);
	//test_proj_aff_scale(10);
	//test_scale_add(10);
	//test_add_sub(10);
	/*
	a->scale_point(1);
	a->affRepr();
	cout << *a << endl;
	cout << *g << endl;
	*/
	

	/*
	//NOTE: ERROR IN ModularArithmetic?
	ModularArithmetic hi = ModularArithmetic(13);
	Integer x = hi.Add(5, 6);
	Integer y = hi.Add(8, 6);
	cout << x << endl; // 5 + 6 = 11 mod 13
	cout << y << endl; // 8 + 6 = 1 mod 13

	cout << hi.Multiply(hi.Add(5, 6), hi.Add(8, 6)) << endl; // 11 * 1 = 4 mod 13 WRONG, WHY?
	cout << hi.Multiply(x, y) << endl; // 11 * 1 = 11 mod 13 CALCULATES FINE HERE
	*/
	/*
	Integer a = 255 - 31;
	while (a > 0) {
		cout << a << " || " << a.GetBit(0) << endl;
		a = a >> 1;
	}
	*/
	/*
	cout << "Intitializing points to test \n";
	ProjPoint* a = new ProjPoint(5, 7, 9);
	extern const Integer l;

	cout << "scaling point \n";
	a->scale_point(l);

	cout << *a << endl;

	cout << "Converting point to affine representation \n";
	a->affRepr();

	cout << *a << endl;
	
	*/
	return 0;
}