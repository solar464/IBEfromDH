#include "stdafx.h"
#include "IBEhelpers.h"

#include <random>
#include <bitset>
#include <aes.h>
#include <osrng.h>
#include <modes.h>


using namespace std;
using namespace CryptoPP;

extern const ECC_point g;
extern const Integer m;
extern const Integer l;
extern AutoSeededRandomPool rng;

PCircuit::PCircuit()
{
	_size = 0;
}

PCircuit::PCircuit(int n)
{
	_size = n;
	b0.reserve(n);
	b1.reserve(n);
}

void PCircuit::set_size(int n)
{
	_size = n;
	b0.reserve(n);
	b1.reserve(n);
}

void PCircuit::addEnc(Keys& k, int index, string bZero, string bOne, bool display)
{
	if (b0.size() == _size || b1.size() == _size) {
		cout << "ERROR in PCircuit, attempted to add too many Enc() calls\n";
		cout << "Inputs:\n" << "index: " << index << ", bZero : " << bZero <<
			", bOne: " << bOne << endl;
		return;
	}

	//void helperP(Keys* k, string hStr, int index, int b, string message, ChameleonCipherText* ct, bool display);
	b0.emplace_back(std::bind(helperP, k, placeholders::_1, index, 0, bZero, placeholders::_2, display));
	b1.emplace_back(std::bind(helperP, k, placeholders::_1, index, 1, bOne, placeholders::_2, display));
}

void PCircuit::getCipher(int i, int b, vector<string> hVec, ChameleonCipherText& ct)
{
	if (i >= _size) {
		cout << "Attempting to access functor in PCircuit with invalid index " << i << endl;
		return;
	}
	if (b == 0 || b == '0')
		b0[i](hVec, ct);
	else if (b == 1 || b == '1')
		b1[i](hVec, ct);
	else {
		cout << "Attempting to access functor in PCircuit with invalid b " << b << endl;
		return;
	}
}

void PCircuit::clear(int n)
{
	if (n < 1 || n == _size) {
		b0.clear();
		b1.clear();
	}
	else {
		_size = n;
		b0.resize(n);
		b0.clear();
		b1.resize(n);
		b1.clear();
	}
}

Label::Label()
{
	_size = 0;
}

Label::Label(int n, bool triv)
{
	_size = n;
	b0.reserve(n);
	b1.reserve(n);
	if (triv) {
		for (int i = 0; i < n; i++) {
			b0.push_back("0");
			b1.push_back("1");
		}
	}
}

Label::Label(int n, vector<string> bZero, vector<string> bOne)
{
	if (bZero.size() != n || bOne.size() != n) {
		cout << "ERROR, attempted to construct GCircuit label with invalid inputs!\n";
		cout << "defined length: " << n << endl;
	}
	else {
		_size = n;
		b0 = bZero;
		b1 = bOne;
	}
}

void Label::set_size(int n, bool trivial)
{
	if (_size == 0) {
		_size = n;
		b0.reserve(n);
		b1.reserve(n);
		if (trivial) {
			for (int i = 0; i < _size; i++) {
				b0.push_back("0");
				b1.push_back("1");
			}
		}
	}
	else {
		cout << "Attempted to set the size of a non trivial Label object\n";
		return;
	}
}

void Label::set(int index, int bit, string toSet)
{
	if (index >= _size) {
		cout << "Attempted to set a key in the labels with invalid index\n";
		cout << "Index = " << index << " ; Bit = " << bit << " ; toSet = " << toSet << endl;
		return;
	}
	if (bit == 0 || bit == '0')
		b0[index] = toSet;
	else if (bit == 1 || bit == '1')
		b1[index] = toSet;
	else {
		cout << "Attempted to set a key in the labels with invalid bits\n";
		cout << "Index = " << index << " ; Bit = " << bit << " ; toSet = " << toSet << endl;
		return;
	}
}

string Label::getLabel(int i, int b) const
{
	if (i < _size && (b == 0 || b == '0'))
		return b0[i];
	else if (i < _size && (b == 1 || b == '1'))
		return b1[i];
	else {
		cout << "Attempted to retrieve data from GCircuit label with invalid inputs\n";
		cout << "i = " << i << " b = " << b << endl;
		return 0;
	}
}

pair<ECC_point,Integer> G(Integer r)
{
	//#r : a random number in p
	return make_pair(ECC_point::scale_point(r, g), r);
}

pair<ECC_point,SecByteBlock> E(ECC_point& ek, string message)
{
	//# ek: encryption key from G()
	//# m : message to encrypt

	//returns
	// rg: r*g, not the same r in G()
	// encrypted: encrypted ciphertext with CFB AES encryption

	Integer r(rng, 0, m - 1);

	ECC_point rEk = ECC_point::scale_point(r, ek);
	Integer	intkey = Extract(rEk);
	SecByteBlock key(32);
	intkey.Encode(key, key.size());

	CFB_Mode<AES>::Encryption cfbEncryption(key, key.size(), key);

	SecByteBlock encrypted(message.length());

	cfbEncryption.ProcessData(encrypted, (byte*)message.c_str(), message.length());
	
	return make_pair(ECC_point::scale_point(r, g), encrypted);
}

string D(Integer dk, ECC_point& rg, SecByteBlock& ct)
{
	//# dk: decryption key from G()
	//  rg: r*g from E()
	//# ct : encrypted ciphertext from E()

	//decrypted: decrypted message

	ECC_point rEk = ECC_point::scale_point(dk, rg);
	Integer intkey = Extract(rEk);
	SecByteBlock key(32);
	intkey.Encode(key, key.size());

	CFB_Mode<AES>::Decryption cfbDecryption(key, key.size(), key);

	//decrypted bytes now in ct
	cfbDecryption.ProcessData(ct, ct, ct.size());

	//convert to string and return
	return string((char*)ct.data(), ct.size());
}

void P(int beta, Keys& k, Label lab, PCircuit& pc, int n, bool display)
{
	if (beta == '0') 
		beta = 0;
	else if (beta == '1') 
		beta = 1;

	pc.set_size(n);
	if (display) cout << "Beginning P() call\n";
	for (int i = 0; i < n; i++) {
		pc.addEnc(k, i + beta*n, lab.getLabel(i, 0), lab.getLabel(i, 1), display);
	}
}

void helperP(Keys& k, vector<string> hVec, int index, int b, string message, ChameleonCipherText& ct, bool display) {
	//used in P to be converted to functor object
	//returns a vector of ChameleonCipherTexts size 1024
	/*
		toReturn = [None for _ in range(lmbd2)]

		for j in range(lmbd2) :
			toReturn[j] = [Enc(k, h, j + beta*lmbd2, 0, lab[j][0] * 16), Enc(k, h, j + beta*lmbd2, 1, lab[j][1] * 16)]

			return toReturn
		*/
	string hStr = "";
	for (int i = 0; i < hVec.size(); i++) {
		hStr += hVec[i];
	}

	if (hStr.length() != 512) {
		cout << "ERROR: hStr passed into P() does not have a length of 512\n";
		cout << "hStr: " << hStr << endl;
	}
	string hxStr = hStr.substr(0, 256);
	//cout << "hxStr: \n" << hxStr << endl;
	string hyStr = hStr.substr(257);
	//cout << "hyStr: \n" << hyStr << endl;

	Integer hx = bin_to_integer(hxStr);
	Integer hy = bin_to_integer(hyStr);

	ECC_point h(hx, hy);
	if (display) cout << "helperP, h: \n" << h << endl;

	Enc(k, h, index, b, message, ct, display);
}


function<pair<ECC_point, SecByteBlock>(vector<string>)> T(string message)
{
	//# message: the message to encrypt, built into circuit ?
	// returns a functor object with std::bind that calculates E(ek,message)

	//for use in Encrypt()
	//placeholder for a circuit that calculates E(ek, m) taking ek as input

	//#ek in the following lambda function is bitstring representing an Ed2559 point
	//# ek is an Ed2559 point, bit string is the x and y coordinates concatenated
	return std::bind(helperT, message, placeholders::_1);
}

pair<ECC_point, SecByteBlock> helperT(string message, vector<string>& ekVec) {
	//used in T to be converted to functor object
	//parses bitstring ekStr to an ECC_point ek and returns E(ek,message)
	string ekStr = "";
	for (int i = 0; i < ekVec.size(); i++)
		ekStr += ekVec[i];
	if (ekStr.length() != 512) {
		cout << "ERROR: ekStr passed into T() does not have a length of 512\n";
		cout << "ekStr: " << ekStr << endl;
		cout << "message: " << message << endl;
	}
	string ekxStr = ekStr.substr(0,256);
	//cout << "ekxStr: \n" << ekxStr << endl;
	string ekyStr = ekStr.substr(257);
	//cout << "ekyStr: \n" << ekyStr << endl;

	Integer ekx = bin_to_integer(ekxStr);
	Integer eky = bin_to_integer(ekyStr);

	//cout << "ekx: \n" << ekx << endl;
	//cout << "eky: \n" << eky << endl;

	ECC_point ek(ekx, eky);
	
	return E(ek, message);
}

pair<ECC_point, SecByteBlock> Eval(function<pair<ECC_point, SecByteBlock>(vector<string>)> garbled, vector<string> input)
{
	return garbled(input);
}

Label GCircuit(function<pair<ECC_point, SecByteBlock>(vector<string>)>& toGarble, int security)
{
	return Label(security);
}

Label GCircuit(PCircuit& toGarble, int security)
{
	return Label(security);
}

string PRF(string s, string v)
{
	cout << "Beginning PRF() call\n";
	string sv = s + v;
	seed_seq seq(sv.begin(), sv.end());
	minstd_rand prng(seq);
	string toReturn = "";

	//cout << "beginning loop to generate bits";
	for (int i = 0; i < (signed int) s.length() - 31; i=i+31) {
		//cout << i << endl;
		//cout << toReturn << endl;
		toReturn = toReturn + bitset<31>(prng()).to_string();
	}
	
	string last31 = bitset<31>(prng()).to_string();
	return toReturn + last31.substr(0, s.length() % 31);
	//cout << "ending PRF() call\n";
}

void testGED(int n, string message,bool display)
{
	//# n : number of different pk, sk pairs to test
	//# message : a custom message to test
	Integer r;
	ECC_point ek, rg;
	Integer dk;
	SecByteBlock encrypted;
	string decrypted;

	pair<ECC_point, Integer> outG;
	pair<ECC_point, SecByteBlock> outE;

	for (int i = 0; i < n; i++) {
		if (display)
			cout << "loop: " << i << endl;

		r = Integer(rng, 0, m - 1);
		if (display) cout << "r: " << r << endl;

		outG = G(r);
		ek = outG.first;
		dk = outG.second;
		if (display) cout << "ek: " << ek << "\ndk: " << dk << endl;

		outE = E(ek, message);
		rg = outE.first;
		encrypted = outE.second;
		if (display) cout << "rg: " << rg << "\nEncrypted: " << string((char*)(byte*)encrypted,encrypted.size()) << endl;

		decrypted = D(dk, rg, encrypted);
		if (display) cout << "decrypted: " << decrypted << endl;

		if (message != decrypted) {
			cout << "ERROR: " << message << " decoded as " << decrypted << endl;
		}
	}
}

void testP(Keys& k, bool display, int loops) {
	//function<void(const string, vector<pair<ChameleonCipherText*, ChameleonCipherText*>> *)> P(int beta, Keys* k, Label lab, int = 512);
	//void helperP(int beta, Keys* k, Label lab,
	//	string hStr, vector<pair<ChameleonCipherText*, ChameleonCipherText*>>* out, int = 512);

	if (k.size() % 2 != 0) cout << "testP, Key table has odd size, will cause problems\n";
	int n = k.size() / 2;

	PCircuit pTilda;
	ChameleonCipherText encrypted0, encrypted1;
	string decrypted, decrypted0, decrypted1;

	for (int j = 0; j < loops; j++) {
		vector<string> b0;
		b0.reserve(n);
		for (int i = 0; i < n; i++)
			b0.push_back(integer_to_bin(Integer(rng, 0, (1 << n) - 1), n));
		vector<string> b1;
		b1.reserve(n);
		for (int i = 0; i < n; i++)
			b1.push_back(integer_to_bin(Integer(rng, 0, (1 << n) - 1), n));
		if (display) {
			for (int i = 0; i < n; i++) {
				cout << "b0 : " << i << " | " << b0[i] << endl;
				cout << "b1 : " << i << " | " << b1[i] << endl;
			}
		}
		Label lab(n, b0, b1);
		int beta = rng.GenerateBit() % 2;
		if (display) cout << "beta: " << beta << endl;

		Integer r(rng, 0, m - 1);
		if (display) cout << "r: " << r << endl;
		string x = integer_to_bin(Integer(rng, 0, (1 << k.size()) - 1), k.size());
		if (display) cout << "x: " << x << endl;
		ECC_point h = Hash(k, x, r);
		h.affRepr();
		if (display) cout << "h: " << h << endl;

		string hStr = integer_to_bin(h.getX(), 256) + integer_to_bin(h.getY(), 256);
		vector<string> hVec(hStr.length());
		for (int i = 0; i < hStr.length(); i++)
			hVec.push_back(strBit(hStr[i]));

		if (display) cout << "Calling P() to obtain PCircuit, contains vectors of functors\n";
		P(beta, k, lab, pTilda, n, display);

		if (display) cout << "Beginning loop to check Enc/Dec with P()\n";
		for (int i = 0; i < n; i++) {
			if (display) cout << "Evaluating functors in PCircuit to obtain ChameleonCipherTexts\n";
			encrypted0 = ChameleonCipherText();
			encrypted1 = ChameleonCipherText();
			pTilda.getCipher(i, 0, hVec, encrypted0);
			pTilda.getCipher(i, 1, hVec, encrypted1);

			if (display) cout << "Decrypting the ChameleonCipherTexts\n";
			decrypted0 = Dec(k, x, r, encrypted0, display);
			decrypted1 = Dec(k, x, r, encrypted1, display);

			if (display) cout << "Checking if Decrypted correctly\n";
			if (x[i + beta*n] == '0')
				decrypted = decrypted0;
			else if (x[i + beta*n] == '1')
				decrypted = decrypted1;
			else {
				cout << "\nERROR: testP, you screwed up regarding bitstrings\n\n";
				continue;
			}

			if (display) {
				cout << "decrypted: " << decrypted << endl;
				cout << "decrypted0: " << decrypted0 << endl;
				cout << "decrypted1: " << decrypted1 << endl;
			}


			if (decrypted != lab.getLabel(i, x[i + beta*n])) {
				cout << "\nERROR: testP, you screwed up implementing P()\n\n";
				cout << "index : " << i + beta*n << endl;
				cout << "decrypted: " << decrypted << endl;
				cout << "x bit: " << x[i + beta*n] << endl;
				cout << "should be: " << lab.getLabel(i, int(x[i + beta*n])) << endl;
			}

		}
	}
}


void testT(int n, string message, bool display) {
	Integer rand, dk;
	pair<ECC_point, Integer>edk; 
	ECC_point ek, rg;
	function<pair<ECC_point, SecByteBlock>(vector<string>)> encryptor;
	pair<ECC_point, SecByteBlock> ciphertext;
	SecByteBlock encrypted;
	string ekStr, decrypted;

	if (display) cout << "Beginning testing of T() using GED\n";
	for (int i = 0; i < n; i++) {
		if (display) cout << "Initializin using G\n";
		rand = Integer(rng, 0, m - 1);
		edk = G(rand);
		ek = edk.first;
		ek.affRepr();
		cout << "ek: " << ek << endl;
		dk = edk.second;
		cout << "dk: " << dk << endl;

		string ekStr = integer_to_bin(ek.getX(), 256) + integer_to_bin(ek.getY(), 256);
		vector<string> ekVec;
		ekVec.reserve(ekStr.length());
		for (int i = 0; i < ekStr.length(); i++)
			ekVec.push_back(ekStr[i] + "");

		cout << "ekStr: \n" << ekStr << endl;

		if (display) cout << "Calling T()\n";
		encryptor = T(message);
		if (display) cout << "Passing argument to result of T(message)\n";
		ciphertext = encryptor(ekVec);
		rg = ciphertext.first;
		encrypted = ciphertext.second;
		cout << "encrypted: " << string((char*)encrypted.data(), encrypted.size()) << endl;

		if (display) cout << "Decrypting\n";
		decrypted = D(dk, rg, encrypted);
		cout << "decrypted: " << decrypted << endl;
		if (display) cout << "End testing to T()\n";
	}
}

