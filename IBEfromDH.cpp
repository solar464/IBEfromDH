#include "stdafx.h"
#include "IBEfromDH.h"
#include "IBEhelpers.h"

#include <eccrypto.h>
#include <osrng.h>

//extern const Integer m;
//extern const Integer l;
//extern const Integer d;
extern AutoSeededRandomPool rng;
const int lmbd = 256;

void Setup(int n, 
	MPK& mpk, MSK& msk, bool display)
{
	//# lmbd: security parameter(? ) = 256 bits for point arithmetic on the Ed2559 curve
	//# n : ID length
	//# sets up the IBE

	//# NodeGen() requires next index, so can't set ID length limit to 1 or less
	if (n < 2) {
		n = 2;
	}
	
	//# 1.
	string s = integer_to_bin(Integer(rng, 0, (Integer(1) << 256) - 1), lmbd);

	//# 2.
	mpk.set_size(n);
	msk.set_size(n);

	//ensure mpk is instance variable of msk
	if (msk.mpk() != &mpk) {
		msk.set_mpk(&mpk);
	}
	
	Keys k;
	Traps t;
	//# Ed25519 points require 512 bits to represent without extra computation
	//# will need to concatenate 2 strings representing Ed25519 points -> 1024 bits
	for (int i = 0; i < n; i++) {
		k = *(new Keys(4 * lmbd));
		t = *(new Traps(4 * lmbd));
		Gen(4 * lmbd, k, t);
		mpk.addKeys(&k);
		msk.addTraps(&t);
	}
	
	//# 3.
	//NodeGen(MSK*, string, string, LocalKey*);
	LocalKey tmp(1);
	NodeGen(msk, s, "", tmp);

	//extract the h_ep value from the NodeGen() call
	mpk.set_h_ep(tmp.hv(0));
	//assign the s string to msk
	msk.set_s(s);

	return;
	//# 4.
	//mpk = (k, h_ep)
	//msk = (mpk, t, s)
}

void KeyGen(MSK& msk, string id, 
	Sk_id& sk_id, bool display) {
	//# msk: master secret key from Setup()
	//# ID : identifies receiver of messages
	//# generates decryption key for ID

	//mpk, t, s = msk
	//k, h_ep = mpk
	MPK* mpk = msk.mpk();
	string s = msk.s();

	int IDlen = id.length();

	//V = [ID[:i] for i in range(IDlen)]

	LocalKey *lk = new LocalKey(IDlen);

	for (int i = 0; i < IDlen - 1; i++) {
		NodeGen(msk, s, id.substr(0, i), *lk, display);
	}

	Integer dkv0, dkv1;
	LeafGen(*(mpk->getKeys(mpk->size()-1)), *(msk.getTraps(msk.size() - 1)), s, id, 
		*lk, dkv0, dkv1, display);

	//dk_id = dk_(ID[1...n - 1] || ID[-1])
	Integer dk_id;
	if (id[IDlen - 1] == '0')
		dk_id = dkv0;
	else if (id[IDlen - 1] == '1')
		dk_id = dkv1;
	else {
		cout << "ERROR: KeyGen(), id is not a bitstring: " << id << endl;
	}

	sk_id.setParams(id, lk, dk_id);
}
void Encrypt(MPK& mpk, string id, string message, 
	IBECipherText& ct, bool display) {
	
	//# mpk: master public key from Setup()
	//# ID : identifies receiver of message
	//# message : message to be encrypted
	//# sk_id : the secret key, used to generate ciphertexts if garbled circuits
	//#			not implemented
	//# trivial: toggles weakening of scheme to speed testing

	//# output stored in an IBECipherText

	int n = id.length();
	ct.set_id_len(n);

	//vector<Keys*> k = mpk._k;
	ECC_point h_ep = mpk.h_ep();

	//#h_ep must be converted to bitstring
	h_ep.affRepr();
	string h_ep_str = integer_to_bin(h_ep.getX(), lmbd) + integer_to_bin(h_ep.getY(), lmbd);

	//#security parameter, since each table of keys is of size(2lmbd) * 2
	//#lmbd = len(k[0]) / 2

	//# 1.
	//# (T~, lab) = GCircuit(lmbd, T[m]), a garbled circuit in actual implementation
	//# m in brackets because known input, ek will be the final result of Ptilda
	function<pair<ECC_point, SecByteBlock>(vector<string>)> Ttilda = T(message);
	Label lab = GCircuit(Ttilda, 2*lmbd);
	//#Ttilda = T(m) #garbled circuits not yet implemented

	//#2.
	
	for (int i = n - 1; i >= 0; i--) {
		PCircuit* Ptilda = new PCircuit(n);
		P(id[i], *(mpk.getKeys(i)), lab, *Ptilda, 2 * lmbd);
		//lab = GCircuit<void>(Ptilda, 2*lmbd);
		//REWRITE WHEN USING NONTRIVIAL LABELS
		lab = Label(2 * lmbd);
		//#Ptilda[i] = P(int(ID[i]), k[i], lab)
		ct.addPCircuit(Ptilda);
	}
	//#3.
	vector<string> lab_h_ep;
	lab_h_ep.reserve(2 * lmbd);
	for (int j = 0; j < 2*lmbd; j++) {
		lab_h_ep.push_back(lab.getLabel(j, h_ep_str[j]));
	}

	ct.setTtilda(&Ttilda);
	ct.setLab(lab_h_ep);
}

string Decrypt(IBECipherText& ct, Sk_id& sk_id, MPK& mpk, bool display) {
	//# ct: ciphertext from Encrypt()
	//# sk_id : decryption key from KeyGen()
	//# mpk : master mpublic key, the public parameters

	//# decrypts the IBECipherText
	//# *evaluates garbled circuits

	//# 1.
	vector<string> *lab = &ct.lab();
	//Ptilda_i = ct.PTilda(i);
	function<pair<ECC_point, SecByteBlock>(vector<string>)>* Ttilda = ct.Ttilda();
	string id = sk_id.id();
	LocalKey* lk = sk_id.lk();
	Integer dk_id = sk_id.dk_id();
	int n = id.length();
	//k[i] = mpk.getKeys(i)
	ECC_point h_ep = mpk.h_ep();
	//vector<Integer> rv = lk->rv();

	if (n != ct.get_id_len()) {
		cout << "ERROR: attempted to decrypt with wrong identity (ID lengths differ)\n";
		return "";
	}

	//#3.
	ECC_point ekv0p = lk->hv0(n-1);
	string ekv0 = integer_to_bin(ekv0p.getX(), lmbd) + integer_to_bin(ekv0p.getY(), lmbd);
	ECC_point ekv1p = lk->hv1(n - 1);
	string ekv1 = integer_to_bin(ekv1p.getX(), lmbd) + integer_to_bin(ekv1p.getY(), lmbd);


	//# 4.
	//# lab = encoded num_to_bin(h_ep[0], lmbd) + num_to_bin(h_ep[1], lmbd)
	string y = integer_to_bin(Extract(h_ep),lmbd);
	string encryption_key;
	//# 5. Following code requires garbled circuits.

	vector<string> *tmp;
	vector<string> *newLab = &vector<string>(2 * lmbd);
	//#recovery of ek from Ptilda
	for (int i = 0; i < n; i++) {
		//# in paper : v = ID[0:i]
		//v = i

		//# a)
		//PCircuit e = Eval<void>(ct.ptilda(i), lab);
		//supposed to evaluate the garbled circuit giving 2 vectors of ChameleonCipherText objects
		//  done below instead to lazily generate
		PCircuit e = *(ct.ptilda(i));

		//# b) the case of i == n - 1
		if (i == n - 1) {
			//# ek_id = ek_(ID[1...n - 1] || ID[-1])
			encryption_key = id[id.length()-1] == '0' ? ekv0 : ekv1;

			for (int j = 0; j < 2 * lmbd; j++) {
				ChameleonCipherText chamCT;
				e.getCipher(j, y[j], *lab, chamCT);
				(*newLab)[j] = Dec(*(mpk.getKeys(i)), ekv0 + ekv1, lk->rv(i), chamCT);
			}
					
		}
		//# c)
		else {
			y = integer_to_bin(Extract(lk->hv(i)), lmbd) + integer_to_bin(Extract(lk->hv(i)), lmbd);
			for (int j = 0; j < 2 * lmbd; j++) {
				string hv0andhv1 = integer_to_bin(Extract(lk->hv0(i)), lmbd) + integer_to_bin(lk->hv0(i).getY(), lmbd) + integer_to_bin(Extract(lk->hv1(i)), lmbd) + integer_to_bin(lk->hv1(i).getY(), lmbd);
				ChameleonCipherText chamCT;
				e.getCipher(j, y[j], lab[j], chamCT);
				(*newLab)[j] = Dec(*(mpk.getKeys(i)), hv0andhv1, lk->rv(i), chamCT);
			}
			tmp = lab;
			lab = newLab;
			newLab = tmp;
			newLab->clear();
		}
		
	}
	//# 6.
	//# Evaluation of T[m](ek)
	//f = Eval(Ttilda, lab) #if using garbled circuits
	pair<ECC_point, SecByteBlock> f = Eval(*(ct.Ttilda()), *newLab);

	//#7.

	//### NOTE TO SELF: yrecover returns one of two valid y values => require a bit designating even or odd y
	//### 	UPDATE: can't compress points without offloading more work to garbled circuit, roughest design for now
	//### NOTE TO SELF: Decrypt() mutates its inputs (lab from ct), decrypting a ciphertext multiple times changes the result
	return D(dk_id, f.first,f.second);

}

void NodeGen(MSK& msk, string s, string v, 
	LocalKey& lk, bool display) {
	//# k: list of keys from Gen()
	//# t : list of trapdoors from Gen()
	//both parameters above are stored in msk

	//# s : seed, bitstring or string(? ), of size 256 bits if using Ed25519
	//# v : node, bitstring

	//# generates intermediate nodes used to generate the encryption key for a person
	//# 	used in KeyGen()

	MPK* mpk = msk.mpk();

	//#lmbd = len(s)
	int i = v.length();

	string zeroBitString = string('0', lmbd * 4);

	ECC_point hv = Hash(*(mpk->getKeys(i)), zeroBitString, bin_to_integer(PRF(s, v)));
	ECC_point hv0 = Hash(*(mpk->getKeys(i + 1)), zeroBitString, bin_to_integer(PRF(s, v + '0')));
	ECC_point hv1 = Hash(*(mpk->getKeys(i + 1)), zeroBitString, bin_to_integer(PRF(s, v + '1')));
	hv.affRepr();
	hv0.affRepr();
	hv1.affRepr();

	//# xprime argument = str(hv0)) + str(hv1), concatentation of x and y values too
	string hv0hv1 = integer_to_bin(hv0.getX(), lmbd) + integer_to_bin(hv0.getY(), lmbd) + 
					integer_to_bin(hv1.getX(), lmbd) + integer_to_bin(hv1.getY(), lmbd);
	Integer rv = HashInv(*(msk.getTraps(i)), zeroBitString, bin_to_integer(PRF(s, v)), hv0hv1);

	lk.addNode(hv, hv0, hv1, rv);
}

void LeafGen(Keys& kn_1, Traps& tn_1, string s, string v,
	LocalKey& lk, Integer& dkv0, Integer& dkv1, bool display) {
	
	//# kn_1: a key from Gen()
	//# tn_1 : a trapdoor corresponding to kn_1 from Gen()
	//# s : seed, bitstring or string(? ), of size 256 bits if using Ed25519
	//# v : node, bitstring

	//# generates the final node used to generate the encryption key for a person
	//# 	used in KeyGen()

	//#lmbd = len(s)
	string zeroBitString = string('0', lmbd * 4);

	ECC_point hv = Hash(kn_1, zeroBitString, bin_to_integer(PRF(s, v)));
	hv.affRepr();

	pair<ECC_point, Integer> ekdk = G(bin_to_integer(PRF(s, v + '0')));
	ECC_point ekv0 = ekdk.first;
	dkv0 = ekdk.second;
	if (display) cout << v << ".dkv0:" << dkv0 << endl;

	ekdk = G(bin_to_integer(PRF(s, v + '1')));
	ECC_point ekv1 = ekdk.first;
	dkv1 = ekdk.second; 
	if (display) cout << v << ".dkv1:" << dkv1 << endl;

	ekv0.affRepr();
	ekv1.affRepr();
	
	//# xprime argument = str(ekv0) + str(ekv1)
	string ekv0ekv1 = integer_to_bin(ekv0.getX(), lmbd) + integer_to_bin(ekv0.getY(), lmbd) +
					  integer_to_bin(ekv1.getX(), lmbd) + integer_to_bin(ekv1.getY(), lmbd);

	Integer rv = HashInv(tn_1, zeroBitString, bin_to_integer(PRF(s, v)), ekv0ekv1);

	lk.addNode(hv, ekv0, ekv1, rv);
}

MPK::MPK()
{
	_size = 0;
}

MPK::~MPK()
{
	for (int i = 0; i < _size; i++) {
		delete _k[i];
	}
}

MPK::MPK(vector<Keys*>& k, ECC_point& a)
{
	_size = k.size();
	_k = k;
	_h_ep = ECC_point(a);
}

bool MPK::set_size(int n)
{
	if (_size == 0) {
		_size = n;
		_k.reserve(n);
		return true;
	}
	cout << "Attempted to set the size of non trivial MPK object\n";
	return false;
}

bool MPK::addKeys(Keys *k)
{
	if (_k.size() >= _size) {
		cout << "Attempted to add too many elements to and MPK object\n";
		return false;
	}

	_k.push_back(k);
	return true;
}

void MPK::set_h_ep(ECC_point & a)
{
	if (_h_ep.isNull()) {
		_h_ep.setPoint(a);
	}
	else {
		cout << "Attempted to set the values of a non trivial MPK object\n";
	}
}

MSK::MSK()
{
	_size = 0;
	_s = "";
}

MSK::~MSK()
{
	delete _mpk;
	for (int i = 0; i < _size; i++) {
		delete _t[i];
	}
}

bool MSK::set_size(int n)
{
	if (_size == 0) {
		_size = 0;
		_t.reserve(n);
		return true;
	}
	cout << "Attempted to set the size of non trivial MSK object\n";
	return false;
}

void MSK::set_mpk(MPK * mpk)
{
	_mpk = mpk;
}

bool MSK::addTraps(Traps *t)
{
	if (_size > _t.size()) {
		_t.push_back(t);
		return true;
	}
	cout << "Attempted to add too many elements to an MSK object\n";
	return false;
}

void MSK::set_s(string s)
{
	_s = s;
}

MSK::MSK(MPK *pblc, vector<Traps *>t, string s)
{
	_mpk = pblc;
	_t = t;
	_s = s;
}

Sk_id::Sk_id()
{
	_id = "";
}

Sk_id::Sk_id(string id, LocalKey *lk, Integer dk)
{
	_id = id;
	_lk = lk;
	_dk_id = dk;
}

bool Sk_id::setParams(string id, LocalKey * lk, Integer dk)
{
	if (_id == "") {
		_id = id;
		_lk = lk;
		_dk_id = dk;
		return true;
	}
	else {
		cout << "Attempted to set the values of a non trivial Sk_id\n";
	}
	return false;
}

LocalKey::LocalKey()
{
	_size = 0;
}

LocalKey::LocalKey(int n)
{
	if (n <= 0) {
		cout << "Attempted to initialize LocalKey object with size : " << n << endl;
		_size = 0;
		return;
	}
	_size = n;
	_hv.reserve(n);
	_hv0.reserve(n);
	_hv1.reserve(n);
	_rv.reserve(n);
}

void LocalKey::set_size(int n)
{
	if (n <= 0) {
		cout << "Attempted to initialize LocalKey object with size : " << n << endl;
		_size = 0;
		return;
	}
	_size = n;
	_hv.reserve(n);
	_hv0.reserve(n);
	_hv1.reserve(n);
	_rv.reserve(n);
}

bool LocalKey::addNode(ECC_point & hv, ECC_point & hv0, ECC_point & hv1, Integer& rv)
{
	if (_hv.size() == _size) {
		cout << "Attempted to add too many elements to a LocalKey object\n";
		cout << "Capacity of the LocalKey object: " << _size << endl;
		return false;
	}
	_hv.emplace_back(hv);
	_hv0.emplace_back(hv0);
	_hv1.emplace_back(hv1);
	_rv.emplace_back(rv);
	return true;
}

IBECipherText::IBECipherText()
{
	return;
}

void IBECipherText::set_id_len(int n)
{
	if (_Ptilda.size() == 0) {
		_Ptilda.reserve(n);
	}
	else {
		cout << "ERROR: attempted to modify size of non trivial IBECipherText\n";
	}
}

void IBECipherText::addPCircuit(PCircuit * p)
{
	if(_Ptilda.size()<_Ptilda.capacity())
		_Ptilda.emplace_back(p);
	else {
		cout << "Attempted to add too many PCircuit objects to a IBECipherText\n";
	}
}
