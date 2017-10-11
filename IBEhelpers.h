#pragma once
#include "ECC_point.h"
#include "Chameleon.h"
using namespace std;

class PCircuit {
	int _size;
	vector <function<void(string, ChameleonCipherText&)>> b0;
	vector <function<void(string, ChameleonCipherText&)>> b1;
public:
	PCircuit();
	PCircuit(int);
	void set_size(int);
	void addEnc(Keys& k,int index, string bZero, string bOne, bool=false);
	void getCipher(int i, int b, string hStr, ChameleonCipherText& ct);
	void clear(int=-1);
};

class Label {
	vector<string> b0;
	vector<string> b1;
	int _size;
public:
	Label();
	Label(int n);
	Label(int n, vector<string> bZero, vector<string> bOne);
	void set_size(int,bool=false);
	void set(int, int, string);
	string getLabel(int i, int b) const;
	int size() const { return _size; }
};

//An asymetric key encryption scheme with Ed25519
pair<ECC_point,Integer> G(Integer r);
pair<ECC_point,SecByteBlock> E(ECC_point& ek, string message);
string D(Integer dk, ECC_point& rg, SecByteBlock& ct);


//functions to serve as placeholders for the garbled circuit functions

void P(int beta, Keys& k, Label lab, PCircuit&, int=512, bool=false);
void helperP(Keys& k, string hStr, int index, int b, string message, ChameleonCipherText& ct, bool display);
function<pair<ECC_point, SecByteBlock>(vector<string>)> T(string message);
pair<ECC_point, SecByteBlock> helperT(string message, vector<string>& ekVec);

template <class T>
T Eval(function<T(vector<string>)>, vector<string>);

template <class T>
Label GCircuit(function<T(vector<string>)>, int);


//returns a bitstring based on s and v, for use in NodeGen and LeafGen
string PRF(string s, string v);


//test the asymmetric key encryption functions
void testGED(int n, string message = "0000", bool=false);
void testP(Keys&, bool = false, int loops = 1);
void testT(int n, string message = "0000", bool = false);

template<class T>
inline T Eval(function<T(vector<string>)> garbled, vector<string> input)
{
	return garbled(input);
}

template<class T>
inline Label GCircuit(function<T(vector<string>)> toGarble, int security)
{
	return Label(security);
}
