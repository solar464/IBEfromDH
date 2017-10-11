#include "stdafx.h"
#include "Chameleon.h"


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
#include <eccrypto.h>
#include <aes.h>


using namespace CryptoPP;
extern const ECC_point g;

extern const ModularArithmetic ma;
extern AutoSeededRandomPool rng;

// 2^255 - 19
extern const Integer m;
// order of the Ed25519 curve
extern const Integer l;

Keys::Keys()
{
	_size = 0;
}

Keys::Keys(int n)
{
	k0.reserve(n);
	k1.reserve(n);
	_size = n;
}

void Keys::add(const ECC_point& b0, const ECC_point& b1)
{
	if (k0.size() < _size && k1.size() <_size) {
		k0.emplace_back(b0);
		k1.emplace_back(b1);
	}
	else
		cout << "Attempted to add too many keys to a Key Object\n";
}

void Keys::set_size(const int n)
{
	if (_size <= 0) {
		_size = n;
		k0.reserve(n);
		k1.reserve(n);
	}
}

void Keys::generate_c(Integer & s, int index)
{
	for (ECC_point& a : k0) a.scale_point(s);
	for (ECC_point& a : k1) a.scale_point(s);
	k0[index].setPoint(0, 0, -1);
	k1[index].setPoint(0, 0, -1);
}

ECC_point Keys::getKey(int i, int b) const
{
	if (i >= _size) {
		cout << "ERROR: attempted to retrieve a Key with invalid index: i = " << i << endl;
		return ECC_point();
	}
	if (b == 0 || b == '0')
		return k0[i];
	else if (b == 1 || b == '1')
		return k1[i];
	else {
		cout << "ERROR: attempted to retrieve a Key with invalid bit: b = " << b << endl;
		return ECC_point();
	}
}


Traps::Traps()
{
	_size = 0;
}

Traps::Traps(int n)
{
	_t.reserve(n);
	_size = n;
}

void Traps::add(const Integer& b0, const Integer& b1)
{
	if (_t.size() < _size)
		_t.emplace_back(make_pair(b0, b1));
	else
		cout << "Attempted to add too many trapdoors\n";
}

void Traps::set_size(const int n)
{
	if (_size == 0) {
		_size = n;
		_t.reserve(n);
	}
}

Integer Traps::getTrap(int i, int b) const
{
	if (i >= _size) {
		cout << "ERROR: attempted to retrieve a Key with invalid index: i = " << i << endl;
		return -1;
	}
	if (b == 0 || b == '0')
		return _t[i].first;
	else if (b == 1 || b == '1')
		return _t[i].second;
	else {
		cout << "ERROR: attempted to retrieve a Key with invalid bit: b = " << b << endl;
		return 0;
	}
}

ChameleonCipherText::ChameleonCipherText()
{
	_encrypted = SecByteBlock();
	_cprime = ECC_point();
	_f = ECC_point();
	_c = Keys();
}

ChameleonCipherText::ChameleonCipherText(SecByteBlock encrypted, ECC_point cprime, ECC_point f, Keys& c)
{
	_encrypted = encrypted;
	_cprime = cprime;
	_f = f;
	_c = c;
}

void Gen(int n, Keys& k, Traps& t, bool display)
{
	// n: an integer
	//returns 2n pairs of keys and trapdoors
	if (display) {
		cout << "Beginning the Gen() call\n";
		cout << "Initializing Keys pointer\n";
	}

	k.set_size(n);

	if(display) cout << "Inititalizing Traps pointer\n";

	t.set_size(n);
	Integer b0, b1;
	
	if(display) cout << "Beginning loop to fill the Keys and Traps objects\n";
	
	for (int i = 0; i < n; i++) {
		b0 = Integer(rng, 0, m - 1);
		b1 = Integer(rng, 0, m - 1);

		//cout << "Adding to Traps\n";
		// a_(j, b) = t[j][b]
		t.add(b0, b1);

		// g_(j, b) = a_(j, b)*g = k[j][b] = t[j][b] * g
		//cout << "Adding to Keys\n";
		k.add(ECC_point::scale_point(b0, g), ECC_point::scale_point(b1,g));
	}

	if(display) cout << "returning the Keys and Traps as a pair and ending Gen() call\n";
}

ECC_point Hash(Keys& k, string x, Integer r, bool display) {
	//k: the list of keys
	//x: a bitstring
	//r: a random number in the finite field of p

	//assumes k,x have the same length
	// returns hash value of x

	if (display) {
		cout << "Beginning the Hash() call\n";
		cout << "Checking that the lengths of Keys and bitstring are equal\n";
	}
	if (k.size() != x.length())
		cout << "k and x have different lengths\n";

	if (display) cout << "Computing r*g\n";
	//hash = r*g + sum(k[j][x[j]] for j in len(x))
	ECC_point hash = ECC_point::scale_point(r, g); //r*g

	if (display) cout << "Using Keys to calculate the rest of the hash\n";
	for (unsigned int i = 0; i < k.size(); i++) {
		//sum(k[j][x[j]] for j in len(x))
		hash.add_points(k.getKey(i, int(x[i])));
	}

	if (display) cout << "Ending Hash() call\n";
	return hash;
}

Integer HashInv(Traps& t, string x, Integer r, string xprime, bool display) {
	// t: the list of trapdoors from Gen
	// x: a bitstring
	// r: the random number in p corresponding to x
	// xprime: another bitstring, should be same length as x

	// returns rprime
	//	s.t. Hash(k,x,r) == Hash(k,xprime,rprime)

	if (display) {
		cout << "Beginning the HashInv() call\n";
		cout << "Checking that the lengths of Traps and bitstrings are equal\n";
	}
	if (t.size() != x.length() || t.size() != xprime.length())
		cout << "t and x and xprime have different lengths\n";

	//rprime = (r + sum(a_(j, x_j) - a_(j, xprime_j)) for j in len(x)) mod p
	Integer rprime = r;

	if (display) cout << "Beginning loop to calculate rprime\n";
	for (unsigned int i = 0; i < t.size(); i++) {
		rprime = rprime + t.getTrap(i, int(x[i])) - t.getTrap(i, int(xprime[i]));
	}

	if (display) cout << "Reducing rprime mod l and ending HashInv() call\n";
	return rprime % l;
}

void Enc(Keys& k, ECC_point h, int index, int b, string message, ChameleonCipherText& ct, bool display) {
	/*
	# k: the list of keys from Gen
	# h: the hash value from Hash
	# index: integer, the index
	# b: a bit, equal to x[index], x will be used in Dec()
	# message: the message to encrypt, character string

	#returns a ciphertext of m with values to decode it

	"""
	lmbd = 256
	m = 16 characters
	h = Ed25519 point
	2.753 seconds per Enc() call
		*using Python's timeit module with 20 repeats
		*Windows 10, quad-core i7 processors 
	"""
	*/
	if (display) {
		cout << "Beginning the Enc() call\n";
		cout << "Initializing s\n";
	}

	SecByteBlock *encrypted = &(ct.encrypted());
	ct.set_c(k);

	Integer s(rng,0,m-1);

	//c_(j,bprime) = s*g_(j,bprime) = s*k[j][bprime]
	if (display) cout << "Calculating c from Keys\n";
	ct.c()->generate_c(s, index);
	
	// in actual implementation, f should be garbled circuit that evaluates s*h
	if (display) cout << "Calculating f = s*h\n";
	ct.set_f(ECC_point::scale_point(s, h));

	//cprime = generate_public_key(s,g)
	if (display) cout << "Calculating cprime = s*g\n";
	ct.set_cprime(ECC_point::scale_point(s, g));

	//kappa = Extract(generate_public_key(s,k[i][b]))
	if (display) cout << "Calculating kappa = Extract( s*k[i][b] )\n";
	ECC_point keyPoint = ECC_point::scale_point(s, k.getKey(index, b));
	Integer kappa = Extract(keyPoint);
	if (display) cout << "KeyPoint: #################" << keyPoint << endl;

	//https://www.cryptopp.com/wiki/Advanced_Encryption_Standard
	//# What mode should be used? Only encrypts 1 bit
	//CFB mode encrypts variable bits I guess

	SecByteBlock key(32);
	kappa.Encode(key, key.size());
	int messageLen = message.length();
	encrypted->resize(messageLen);

	if (display) cout << "Constructing AES encryption object with CFB mode\n";
	CFB_Mode<AES>::Encryption cfbEncryption(key, key.size(), key);
	//using key as Initialization Vector as well;
	if (display) cout << "Encrypting message" << message << endl;
	cfbEncryption.ProcessData(*encrypted, (byte*)message.c_str(), message.length());

	//return (e,cprime,f,c)
	if (display) cout << "Constructing and returning ChameleonCipherText and ending Enc() call\n";
}

//Decrypts the ChameleonCipherText from Enc() above
string Dec(Keys& k, string x, Integer r, ChameleonCipherText& ct, bool display) {
	if (display) {
		cout << "Begin Dec() call\n";
		cout << "Extracting elements from the ChameleonCipherText\n";
	}

	SecByteBlock encrypted = ct.encrypted();
	if (display) cout << "encrypted:\n" << string((char*)(byte*)encrypted.data(), encrypted.size()) << endl;

	ECC_point cprime = ct.cprime();
	if (display) cout << "cprime: \n" << cprime << endl;

	ECC_point f = ct.f();
	if (display) cout << "f:\n" << f << endl;
	///Keys* c = ct->c();

	SecByteBlock decrypted(encrypted.size());

	//# in actual implementation need to evaluate f first
	//# f = eval(f)

	// c_(i, x_i) = f - (r*cprime) - sum(c_(j, x_j))
	if (display) cout << "Calculating f - r*cprime\n";
	cprime.scale_point(r);
	ECC_point keyPoint = ECC_point::subtract_points(f, cprime);

	if (display) {
		cout << "Calculating the keyPoint\n";
		cout << "klen: " << k.size() << endl;
		cout << "c len: " << ct.c()->size() << endl;
	}
	for (unsigned int i = 0; i < ct.c()->size(); i++) {
		ECC_point c_jxj = ct.c()->getKey(i, int(x[i]));
		if (c_jxj.isNull())
			continue;
		keyPoint.subtract_points(c_jxj);
	}

	if (display) cout << "Extracting the AES key from keyPoint\n";
	Integer kappa = Extract(keyPoint);
	if (display) cout << "KeyPoint: #################" << keyPoint << endl;
	SecByteBlock key(32);
	kappa.Encode(key, key.size());

	if (display) cout << "Constructing a AES Decryption object with the key\n";
	CFB_Mode<AES>::Decryption cfbDecryption(key, key.size(), key);
	//Using key as Initialization Vector as well
	if (display) cout << "Decrypting the ciphertext from ChameleonCipherText\n";
	cfbDecryption.ProcessData((byte*)decrypted, (byte*)encrypted, encrypted.size());

	/*
	if (display) cout << "Deleting the ChameleonCipherText\n";
	delete ct;
	*/
	if (display) cout << "Returning the decrypted message and ending the Dec() call\n";
	return string((char*)(byte*)decrypted, decrypted.size());
}

//extracts a key from an ECC_point, the x coordinate of the affine representation
Integer Extract(ECC_point& a) {
	a.affRepr();
	return a.getX();
}
//overloaded Extract() for const ECC_point objects
Integer Extract(const ECC_point& a) {
	if (a.getZ() == 1)
		return a.getX();
	else {
		Integer invZ = Ed_inv(a.getZ());
		return ma.Multiply(invZ, a.getX());
	}
}



//converts the Integer to a binary string
string integer_to_bin(Integer a, int size) {
	string toReturn = "";
	for (int i = size - 1; i >= 0; i--) {
		if (a.GetBit(i)) // i-th bit is 1
			toReturn = toReturn + "1";
		else
			toReturn = toReturn + "0";
	}
	return toReturn;
}

//converts a binary string to an Integer
Integer bin_to_integer(string a) {
	Integer result = 0;
	Integer base = 1;
	for (int i = a.length() - 1; i >= 0; i--){
		if (a[i] == '1')
			result = result + base;
		base = base << 1;
	}
	return result;
}

void testHash(Keys& k, Traps& t, int n, bool display)
{
	int klen = k.size();
	if (klen != t.size()) {
		cout << "the Keys and Trapdoors have different lengths.\n";
		return;
	}

	for (int i = 0; i < n; i++) {
		if (display) {
			cout << "loop " << i << endl;
		}
		string x = integer_to_bin(Integer(rng,0,(1<<klen)-1),klen), xprime = integer_to_bin(Integer(rng, 0, (1 << klen) - 1), klen);
		Integer r(rng, 0, m - 1);
		ECC_point xHash = Hash(k, x, r,display);
		Integer rprime = HashInv(t, x, r, xprime,display);
		ECC_point xprimeHash = Hash(k, xprime, rprime,display);
		xHash.affRepr();
		xprimeHash.affRepr();
		if (xHash != xprimeHash) {
			cout << "You screwed up the Hash,HashInv functions.\n";
		}
		if(display){
			cout << "x: \n" << x << endl;
			cout << "xprime: \n" << xprime << endl;
			cout << "r:\n" << r << endl;
			cout << "rprime:\n" << rprime << endl;
			cout << "xHash:\n" << xHash << endl;
			cout << "xprimeHash:\n" << xprimeHash << endl;
		}
	}
}

void testEncDec(Keys& k, Traps& t, int n, bool display)
{
	int klen = k.size();
	if (klen != t.size()) {
		cout << "the Keys and Trapdoors have different lengths.\n";
		return;
	}

	for (int i = 0; i < n; i++) {
		if (display) {
			cout << "loop " << i << endl;
			cout << "Initializing x,r,index,b,h, message\n";
		}
		string x = integer_to_bin(Integer(rng, 0, (1 << klen) - 1), klen);
		SecByteBlock messageBlock = SecByteBlock(40);
		rng.GenerateBlock(messageBlock, messageBlock.size());
		string message((char*)(byte*)messageBlock, messageBlock.size());
		Integer r(rng, 0, m - 1);
		int index = rand() % klen;
		int b = int(x[index]);
		ECC_point h = Hash(k, x, r, display);

		ChameleonCipherText ct;
		Enc(k, h, index, b, message, ct, display);

		string decrypted = Dec(k, x, r, ct, display);
		
		if (message != decrypted) {
			cout << "You screwed up the Enc, Dec functions.\n";
			cout << "message: \n" << message << endl;
			cout << "messagelen\n" << message.length() << endl;
			cout << "decrypted: \n" << decrypted << endl;
			cout << "decrypted len \n" << decrypted.length() << endl;
		}
		if(display){
			cout << "x: \n" << x << endl;
			cout << "r:\n" << r << endl;
			cout << "h:\n" << h << endl;
			cout << "message: \n" << message << endl;
			cout << "decrypted\n" << decrypted << endl;
		}
	}
}

