#pragma once
#include "IBEhelpers.h"

#include <bitset>
using namespace std;
using namespace CryptoPP;

class LocalKey {
	int _size;
	vector<ECC_point> _hv;
	vector<ECC_point> _hv0;
	vector<ECC_point> _hv1;
	vector<Integer> _rv;
public:
	LocalKey();
	LocalKey(int);
	void set_size(int);
	bool addNode(ECC_point&, ECC_point&, ECC_point&, Integer&);
	ECC_point hv(int i) { return _hv[i]; }
	ECC_point hv0(int i) { return _hv0[i]; }
	ECC_point hv1(int i) { return _hv1[i]; }
	Integer rv(int i) { return _rv[i]; }
};

class Sk_id {
	string _id;
	LocalKey* _lk;
	Integer _dk_id;

public:
	Sk_id();
	Sk_id(string, LocalKey*, Integer);
	~Sk_id() { delete _lk; }
	bool setParams(string id, LocalKey *lk, Integer dk);
	string id() { return _id; }
	LocalKey* lk() { return _lk; }
	Integer dk_id() { return _dk_id; }
};

class MPK {
	int _size;
	vector<Keys*> _k;
	ECC_point _h_ep;
public:
	MPK();
	~MPK();
	MPK(vector<Keys*>&, ECC_point&);
	bool set_size(int);
	bool addKeys(Keys*);
	void set_h_ep(ECC_point&);
	int size() { return _size; }
	Keys* getKeys(int i) const { return _k[i]; }
	ECC_point h_ep() const { return _h_ep; }
};

class MSK {
	int _size;
	MPK* _mpk;
	vector<Traps*> _t;
	string _s;

public:
	MSK();
	~MSK();
	MSK(MPK*, vector<Traps*>,string);
	bool set_size(int);
	void set_mpk(MPK* mpk);
	bool addTraps(Traps*);
	void set_s(string);
	int size() { return _size; }
	MPK* mpk() const { return _mpk; }
	Traps* getTraps(int i) const { return _t[i]; }
	string s() const { return _s; }
};

class IBECipherText {
	vector<string> _lab;
	vector<PCircuit*> _Ptilda;
	function<pair<ECC_point, SecByteBlock>(vector<string>)> _Ttilda;
public:
	IBECipherText();
	~IBECipherText() { for (PCircuit* p : _Ptilda) delete p; }
	void setLab(vector<string>& lab) { _lab = lab; }
	void set_id_len(int n);
	int get_id_len() { return _Ptilda.size(); }
	void addPCircuit(PCircuit* p);
	void setTtilda(function<pair<ECC_point, SecByteBlock>(vector<string>)>* t) { _Ttilda = *t; }
	vector<string>& lab() { return _lab; }
	PCircuit* ptilda(int i) { return _Ptilda[i]; }
	function<pair<ECC_point, SecByteBlock>(vector<string>)>* Ttilda() { return &_Ttilda; }
};

void Setup(int n,
	MPK& mpk, MSK& msk, bool display = false);
void KeyGen(MSK& msk, string id,
	Sk_id& sk_id, bool display = false);
void Encrypt(MPK&, string id, string message,
	IBECipherText& ct, bool display = false);
string Decrypt(IBECipherText& ct, Sk_id& sk_id, MPK& mpk, bool display = false);

void NodeGen(MSK& msk, string s, string v,
	LocalKey& lk, bool display = false);
void LeafGen(Keys& kn_1, Traps& tn_1, string s, string v,
	LocalKey& lk, Integer& dkv0, Integer& dkv1, bool display = false);
