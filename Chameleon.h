#pragma once

#include "ECC_point.h"
using namespace std;
class Keys
{
	std::vector<ECC_point> k0;
	std::vector<ECC_point> k1;
	int _size;
	public:
		Keys();
		Keys(int);
		void add(const ECC_point&, const ECC_point&);
		void set_size(int);
		//for use in Enc()
		void generate_c(Integer& s, int index);
		ECC_point getKey(int, int) const;
		int size() const { return _size; }
};

class Traps
{
	std::vector<pair<const Integer,const Integer>> _t;
	int _size;
	public:
		Traps();
		Traps(int);
		//~Traps() {}
		void add(const Integer&, const Integer&);
		void set_size(const int);
		Integer getTrap(int, int) const;
		pair<const Integer, const Integer> getPair(int i) const { return _t[i]; }
		int size() const { return _size; }
};

class ChameleonCipherText {
	SecByteBlock _encrypted;
	ECC_point _cprime;
	ECC_point _f;
	Keys _c;
  public:
	ChameleonCipherText();
	ChameleonCipherText(SecByteBlock, ECC_point, ECC_point, Keys&);
	//~ChameleonCipherText() { delete _c; }
	void set_encrypted(SecByteBlock& e) { _encrypted = e; }
	void set_cprime(ECC_point& cp) { _cprime.setPoint(cp); }
	void set_f(ECC_point& f) { _f.setPoint(f); }
	void set_c(Keys& k) { _c = k; }
	SecByteBlock& encrypted() { return _encrypted; }
	ECC_point& cprime() { return _cprime; }
	ECC_point& f() { return _f; }
	Keys* c() { return &_c; }
};

/*
Setup
KeyGen
Encrypt
Decrypt
NodeGen
LeafGen
*/
/*
*************************************************
##########  Chameleon Encryption  ###############
*************************************************
Gen(n) :
	# n : an integer
	#returns 2n pairs of keys and trapdoors

	Hash(k, x, r) :
	# k : the list of keys from Gen()
	# x : a bitstring
	# r : a random number in the finite field of p
	#assumes k, x have the same length
	# returns hash value of x
	# hash = r*g + sum(k[j][x[j]] for j in len(x))

	HashInv(t, x, r, xprime) :
	# t : the list of trapdoors from Gen()
	# x : a bitstring
	# r : the random number in p corresponding to x
	# xprime : another bitstring, should be same length as x
	# returns rprime
	#	s.t.Hash(k, x, r) == Hash(k, xprime, rprime)

	Enc(k, h, i, b, m) :
	# k : the list of keys from Gen()
	# h : the hash value from Hash()
	# i : integer, the index
	# b : a bit equal to x[i], x is the bitstring used to generate h
	# m : the message to encrypt
	#returns a ciphertext of m with values to decode it

	Dec(k, x, r, ct) :
	# k : list of keys from Gen()
	# x : bitstring, the same that was hashed and used in Enc()
	# r : random integer in p, the same that was used in Hash()
	# ct : ciphertext, the output from Enc()
	# returns decrypted message
*/

void Gen(int,Keys&,Traps&,bool=false);
ECC_point Hash(Keys&, string, Integer,bool=false);
Integer HashInv(Traps&, string, Integer, string,bool=false);
void Enc(Keys&, ECC_point, int, int, string, ChameleonCipherText&, bool=false);
string Dec(Keys&, string, Integer, ChameleonCipherText&,bool=false);

Integer Extract(ECC_point& a);
Integer Extract(const ECC_point& a);


// TESTING FUNCTIONS
string integer_to_bin(Integer,int);
Integer bin_to_integer(string a);

//test the chameleon encryption functions
void testHash(Keys&, Traps&, int, bool = false);
void testEncDec(Keys&, Traps&, int, bool = false);
