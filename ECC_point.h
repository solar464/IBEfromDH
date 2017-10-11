#include <Integer.h>
#include <nbtheory.h>
#include <modarith.h>
#include <eccrypto.h>

using namespace CryptoPP;
using namespace std;

#pragma once
class ECC_point
{
private:
	Integer x, y, z;
public:
	ECC_point() { x = -1; y = -1; z = -1; }
	ECC_point(const Integer&, const Integer&, const Integer&);
	ECC_point(const Integer&, const Integer&);
	ECC_point(const ECC_point*);
	ECC_point(const ECC_point&);
	//static functions return a new object
	//instance methods are mutator functions when implemented
	//template functions must be implemented in the header file
	static ECC_point add_points(const ECC_point& a, const ECC_point& b);
	static ECC_point double_point(const ECC_point& a);
	static ECC_point scale_point(const Integer& x, const ECC_point& a,bool=false);
	static ECC_point invert_point(const ECC_point& a);
	static ECC_point subtract_points(const ECC_point&, const ECC_point&);

	static ECC_point add_points_aff(const ECC_point& a, const ECC_point& b);
	static ECC_point double_point_aff(const ECC_point& a);
	static ECC_point subtract_points_aff(const ECC_point& a, const ECC_point& b);
	
	ECC_point deepCopy() const { return ECC_point(x, y, z); }
	bool isNull() const { return z == -1; }

	Integer getX() const { return x; }
	Integer getY() const { return y; }
	Integer getZ() const { return z; }
	void add_points(const ECC_point&);
	void double_point();
	void scale_point(const Integer&);
	void invert_point();
	void subtract_points(const ECC_point&);
	void setPoint(const ECC_point&);
	void setPoint(const Integer&, const Integer&, const Integer&);

	void affRepr();

	void add_points_aff(const ECC_point&);
	void double_point_aff();
	void scale_point_aff(const Integer&);
	void subtract_points_aff(const ECC_point&);
};

//for printing
std::ostream& operator<<(std::ostream&, const ECC_point&);

//for equality checking
bool operator==(const ECC_point&, const ECC_point&);
bool operator!=(const ECC_point&, const ECC_point&);

/***********************************************************

Functions for arithmetic on the Ed25519 curve 
	and finite field of 2^255 - 19

************************************************************/

Integer Ed_inv(const Integer&);
Integer Ed_sqrt(const Integer&);
Integer Ed_yrecover(const Integer&);
Integer Ed_xrecover(const Integer&);

Integer Ed_proj_yrecover(const Integer&, const Integer&);
Integer Ed_proj_xrecover(const Integer&, const Integer&);

/***********************************************************

Functions for testing

************************************************************/

ECC_point randProjPoint();
ECC_point randAffPoint();
ECC_point randPoint();
bool is_Ed_point(const ECC_point&);
void test_proj_aff_add_double(int, bool=false);
void test_proj_aff_scale(int, bool=false);
void test_scale_add(int, bool=false);
void test_add_sub(int, bool = false);
