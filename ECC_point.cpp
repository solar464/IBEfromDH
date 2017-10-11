#include "stdafx.h"
#include "ECC_point.h"

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
#include <nbtheory.h>
#include <modarith.h>
#include <eccrypto.h>
#include <osrng.h>

using namespace CryptoPP;

const Integer gx("48124660576694895147914813076284018110470804336376098912894897995932653867602");
const Integer gy("46316835694926478169428394003475163141307993866256225615783033603165251855960");
const Integer gz("1");

extern const ECC_point g = ECC_point(gx, gy,gz);

extern const Integer m = (Integer("1") << 255) - 19;
extern const ModularArithmetic ma(m);

const ECC_point negG = ECC_point(m - gx, gy, gz);

extern const ECC_point projZero = ECC_point(0, 1, 1);

extern const Integer d("20800338683988658368647408995589388737092878452977063003340006470870624536394");
extern const Integer l = (Integer("1") << 252) + Integer("27742317777372353535851937790883648493");

AutoSeededRandomPool rng;

ECC_point::ECC_point(const Integer& X, const Integer& Y, const Integer& Z) {
	x = X; y = Y; z = Z;
}

ECC_point::ECC_point(const Integer & X, const Integer & Y)
{
	x = X; y = Y; z = 1;
}

ECC_point::ECC_point(const ECC_point* a) {
	x = a->getX(); y = a->getY(); z = a->getZ();
}

ECC_point::ECC_point(const ECC_point& a) {
	x = a.getX(); y = a.getY(); z = a.getZ();
}

ECC_point ECC_point::add_points(const ECC_point& a, const ECC_point& b) {
	ECC_point c = a.deepCopy();
	c.add_points(b);
	return c;
};

ECC_point ECC_point::double_point(const ECC_point& a) {
	ECC_point c = a.deepCopy();
	c.double_point();
	return c;
};

ECC_point ECC_point::scale_point(const Integer& x, const ECC_point& a, bool aff) {
	ECC_point c = a.deepCopy();
	//cout << "within ECC_point::scale_point before scaling\n" << c << endl;
	c.scale_point(x);
	//cout << "within ECC_point::scale_point after scaling \n" << c << endl;
	if (aff)
		c.affRepr();
	return c;
};

ECC_point ECC_point::invert_point(const ECC_point& a) {
	ECC_point c = a.deepCopy();
	c.invert_point();
	return c;
}
ECC_point ECC_point::subtract_points(const ECC_point & a, const ECC_point & b)
{
	ECC_point c = ECC_point::invert_point(b);
	c.add_points(a);
	return c;
}

ECC_point ECC_point::add_points_aff(const ECC_point & a, const ECC_point & b)
{
	ECC_point c = a.deepCopy();
	c.add_points_aff(a);
	return c;
}

ECC_point ECC_point::double_point_aff(const ECC_point & a)
{
	ECC_point c = a.deepCopy();
	c.double_point_aff();
	return c;
}

ECC_point ECC_point::subtract_points_aff(const ECC_point & a, const ECC_point & b)
{
	ECC_point c = ECC_point::invert_point(b);
	c.add_points_aff(a);
	return c;
}

void ECC_point::add_points(const ECC_point& b)
{
	// Ed2559_high_level_add_points() in high_level_ECC.py
	Integer x1 = x;
	Integer y1 = y;
	Integer z1 = z;
	Integer x2 = b.getX();
	Integer y2 = b.getY();
	Integer z2 = b.getZ();

	Integer A = ma.Multiply(z1, z2);
	Integer B = ma.Multiply(A, A);
	Integer C = ma.Multiply(x1, x2);
	Integer D = ma.Multiply(y1, y2);
	Integer dD = ma.Multiply(d, D);
	Integer E = ma.Multiply(C, dD);
	Integer F = ma.Subtract(B, E);
	Integer G = ma.Add(B, E);
	//NOTE: H = ma.Multiply(ma.Add(x1,y1), ma.Add(x2,y2)) produces a different H value from the following;
	Integer x1plusy1 = ma.Add(x1,y1), x2plusy2 = ma.Add(x2,y2);
	Integer H = ma.Multiply(x1plusy1, x2plusy2);
	//Perhaps there are errors in the implementation of ModularArithmetic?

	Integer AF = ma.Multiply(A, F);
	Integer CplusD = ma.Add(C, D);
	Integer H_C_D = ma.Subtract(H, CplusD);
	Integer AG = ma.Multiply(A,G);
	Integer FG = ma.Multiply(F,G);
	
	//mutate point to the result
	x = ma.Multiply(AF,H_C_D);
	Integer D_C = ma.Subtract(D, C);
	y = ma.Multiply(AG, D_C);
	z = FG;

	/*
	cout << "A: " << A << endl;
	cout << "B: " << B << endl;
	cout << "C: " << C << endl;
	cout << "D: " << D << endl;
	cout << "E: " << E << endl;
	cout << "F: " << F << endl;
	cout << "G: " << G << endl;
	cout << "H: " << H << endl;
	cout << "x1+y1: " << ma.Add(x1, y1) << endl;
	cout << "x2+y2: " << ma.Add(x2, y2) << endl;
	cout << "AF: " << AF << endl;
	cout << "H_C_D: " << H_C_D << endl;
	cout << "AG: " << AG << endl;
	cout << "FG: " << FG << endl;
	cout << "x3: " << x3 << endl;
	cout << "y3: " << y3 << endl;
	cout << "z3: " << z3 << endl;
	*/

	//std::cout << "Finished Calculation" << endl;	
	//std::cout << "Values of point mutated to result" << endl;
}

void ECC_point::double_point()
{
	// Ed2559_high_level_double_point() in high_level_ECC.py

	Integer x1 = x;
	Integer y1 = y;
	Integer z1 = z;

	Integer x1plusy1 = ma.Add(x1, y1);
	Integer B = ma.Square(x1plusy1);
	Integer C = ma.Square(x1);
	Integer D = ma.Square(y1);
	Integer E = ma.Add(C,D);
	Integer H = ma.Square(z1);
	Integer HH = ma.Double(H);
	Integer J = ma.Subtract(E,HH);
	Integer B_E = ma.Subtract(B,E);
	Integer C_D = ma.Subtract(C,D);

	//mutate point to result
	x = ma.Multiply(B_E,J);
	y = ma.Multiply(E,C_D);
	z = ma.Multiply(E,J);
}

void ECC_point::scale_point(const Integer& e)
{
	//cout << "Checking for zero exponent \n";
	if (e == 0) {
		x = 0;
		y = 1;
		z = 1;
		return;
	}

	//cout << "Assigning variables \n";
	ECC_point* base = this;

	Integer expo = e;

	ECC_point result;

	if (expo.GetBit(0) == 0) {
		result = ECC_point(projZero);
	}
	else {
		result = this->deepCopy();
	}
	expo = expo >> 1;

	//cout << "Beginning double and add loop \n";
	// calculate scalar multiple with double-and-add
	while (expo > 0) {
		base->double_point();
		if (expo.GetBit(0) == 1) {
			result.add_points(base);
		}
		//cout << "Base :" << *base << endl;
		//cout << "Subresult: " << *result << endl;
		expo = expo >> 1;
	}

	//cout << "Assigning results values to the point \n";
	//mutate this to the result
	x = result.getX();
	y = result.getY();
	z = result.getZ();
	//cout << "x : " << x << endl;
	//cout << "y : " << y << endl;
	//cout << "z : " << z << endl;

	//cout << "Deleting temporary point constructed for scaling \n";
	//result is not returned
	//smart pointer used so explicit delete not necessary
	//delete result;
}

void ECC_point::invert_point()
{
	x = m - x;
}

void ECC_point::subtract_points(const ECC_point& a)
{
	this->add_points(ECC_point::invert_point(a));
}

void ECC_point::setPoint(const ECC_point& a)
{
	x = a.getX();
	y = a.getY();
	z = a.getZ();
}

void ECC_point::setPoint(const Integer& X, const Integer& Y, const Integer& Z)
{
	x = X; y = Y; z = Z;
}

void ECC_point::affRepr()
{
	Integer invZ = Ed_inv(z);
	x = ma.Multiply(x,invZ);
	y = ma.Multiply(y,invZ);
	z = 1;
}

void ECC_point::add_points_aff(const ECC_point& b)
{
	if (z != 1) {
		this->affRepr();
	}
	// The following code was taken from the website below and modified
	//	https://ed25519.cr.yp.to/python/ed25519.py
	Integer x1 = x;
	Integer	y1 = y;
	Integer x2 = b.getX();
	Integer y2 = b.getY();
	Integer z2 = b.getZ();

	//convert b to affine representation if needed
	if (z2 != 1) {
		Integer invZ = Ed_inv(z2);
		x2 = ma.Multiply(x2,invZ);
		y2 = ma.Multiply(y2,invZ);
	}

	//Integer x3 = (x1*y2 + x2*y1) * inv(1 + d*x1*x2*y1*y2);
	Integer x1y2 = ma.Multiply(x1, y2);
	Integer x2y1 = ma.Multiply(x2, y1);
	Integer y1y2 = ma.Multiply(y1, y2);
	Integer x1x2 = ma.Multiply(x1, x2);
	Integer xxyy = ma.Multiply(x1x2, y1y2);
	Integer dxxyy = ma.Multiply(d, xxyy);

	Integer x1y2plusx2y1 = ma.Add(x1y2, x2y1), inv1plusDxxyy = Ed_inv(1 + dxxyy);

	x = ma.Multiply(x1y2plusx2y1, inv1plusDxxyy);
	// originally y3 = (y1*y2 - x1*x2) * inv(1 - d*x1*x2*y1*y2);
	// altered to match Bernstein's paper
	//Integer	y3 = (y1*y2 - x1*x2) * inv((1 - d*x1*x2*y1*y2) % m);
	Integer y1y2_x1x2 = ma.Subtract(y1y2, x1x2), inv1_dxxyy = Ed_inv(1 - dxxyy);
	y = ma.Multiply(y1y2_x1x2, inv1_dxxyy);
}

void ECC_point::double_point_aff()
{
	// The following code was taken from the website below and modified
	//	https://ed25519.cr.yp.to/python/ed25519.py
	if (z != 1) {
		this->affRepr();
	}

	Integer x1 = x;
	Integer y1 = y;
	Integer xx1 = ma.Multiply(x1,x1);
	Integer yy1 = ma.Multiply(y1,y1);
	Integer xy1 = ma.Multiply(x1,y1);

	//x3 = (2 * x1*y1) * inv(1 + d*(x1**2)*(y1**2))
	//# originally y3 = (y1*y2 - x1*x2) * inv(1 - d*x1*x2*y1*y2)
	//# altered to match Bernstein's paper
	//y3 = ((y1**2) - (x1**2)) * inv((1 - d*(x1**2)*(y1**2)))
	Integer xy1double = ma.Double(xy1);
	Integer xxyy = ma.Multiply(xx1, yy1);
	Integer dxxyy = ma.Multiply(d, xxyy);
	Integer xDenom = Ed_inv(ma.Add(1,dxxyy));
	
	x = ma.Multiply(xy1double, xDenom);
	Integer yy_xx = ma.Subtract(yy1,xx1);
	Integer yDenom = Ed_inv(ma.Subtract(1, dxxyy));
	y = ma.Multiply(yy_xx, yDenom);
}

void ECC_point::scale_point_aff(const Integer& e) {
	//cout << "Checking for zero exponent \n";
	if (z != 1) {
		this->affRepr();
	}
	if (e == 0) {
		x = 0;
		y = 1;
		return;
	}

	//cout << "Assigning variables \n";
	ECC_point* base = this;

	Integer expo = e;

	ECC_point result;

	if (expo.GetBit(0) == 0) {
		result = ECC_point(projZero);
	}
	else {
		result = this->deepCopy();
	}
	expo = expo >> 1;

	//cout << "Beginning double and add loop \n";
	// calculate scalar multiple with double-and-add
	while (expo > 0) {
		base->double_point_aff();
		if (expo.GetBit(0) == 1) {
			result.add_points_aff(base);
		}
		//cout << "Base :" << *base << endl;
		//cout << "Subresult: " << *result << endl;
		expo = expo >> 1;
	}

	//cout << "Assigning results values to the point \n";
	//mutate this to the result
	x = result.getX();
	y = result.getY();
	//cout << "x : " << x << endl;
	//cout << "y : " << y << endl;

	//cout << "Deleting temporary point constructed for scaling \n";
	//result is not returned
	//smart pointer used so explicit delete not necessary
	//delete result;
}

void ECC_point::subtract_points_aff(const ECC_point &a)
{
	this->add_points_aff(ECC_point::invert_point(a));
}

//for printing points
std::ostream& operator<<(std::ostream &strm, const ECC_point &a) {
	strm << "ECC_point(" << "Integer(\"" << a.getX() << "\"), Integer(\"" << a.getY() << "\"), Integer(\"" << a.getZ() << "\"));";
	return strm;
}

//for equality checking, does not convert projective points to affine to check against affine points
bool operator==(const ECC_point &a, const ECC_point &b) {
	return (a.getX() == b.getX()) && (a.getY() == b.getY()) && (a.getZ() == b.getZ());
}
bool operator!=(const ECC_point &a, const ECC_point &b) {
	return (a.getX() != b.getX()) && (a.getY() != b.getY()) && (a.getZ() != b.getZ());
}


/***********************************************************

Functions for arithmetic on the Ed25519 curve
and finite field of 2^255 - 19

# The following code was taken from the website below and modified
#https://ed25519.cr.yp.to/python/ed25519.p
************************************************************/
//using the <nbtheory.h>, <modarith.h> headers here
Integer Ed_inv(const Integer& z) {
	return ma.Exponentiate(z, m - 2);
};

//for use in Ed_sqrt, not really sure why though
//Integer I = expmod(2, (m - 1) / 4, m);
Integer I = ma.Exponentiate(2, (m - 1) >> 2);

Integer Ed_sqrt(const Integer& aa) {
	Integer a = ma.Exponentiate(aa, (m + 3) >> 3);
	if (ma.Multiply(a, a) - aa != 0) {
		a = ma.Multiply(a, I);
	}
	if (a.GetBit(0) != 0) {
		a = m - a;
	}
	
	if (ma.Multiply(a, a) == aa) {
		return a;
	}
	else {
		return m;
	}
};
Integer Ed_yrecover(const Integer& X) {
	//# X ^ 2 + Y ^ 2 = 1 + d*X ^ 2 * Y ^ 2
	//# X ^ 2 - 1 = Y ^ 2 * (d*X ^ 2 - 1)
	//# Y ^ 2 = (X ^ 2 - 1)*inv(d*X ^ 2 - 1)

	//# returns Y given X
	if (X == 0)
		return Integer("1");
	Integer XX = ma.Multiply(X, X);
	Integer dXX = ma.Multiply(d, XX);
	Integer yyDenom = Ed_inv(ma.Subtract(dXX,1));
	Integer YY = ma.Multiply((XX - 1), yyDenom);
	Integer Y = Ed_sqrt(YY);
	//assert(XX + Y*Y) % Ed25519_m == (1 + Ed25519_d*XX*Y*Y) % Ed25519_m;
	if (Y == m) {
		std::cout << "ERROR in affine_yrecover: cannot recover y-value for" << X << endl;
	}
	return Y;
};
Integer Ed_xrecover(const Integer& y) {
	//X**2 + Y**2 = c**2 * (1 + d * X**2 * Y**2)
	//c = 1
	//X**2 * (1 - d * Y**2) = 1 - Y**2
	if (y == 0)
		return Integer("1");
	Integer yy = ma.Multiply(y, y);
	Integer dyy = ma.Multiply(d, yy);
	Integer xxDenom = Ed_inv(ma.Subtract(dyy, 1));
	Integer xx = ma.Multiply((yy - 1), xxDenom);
	return Ed_sqrt(xx);
}
Integer Ed_proj_yrecover(const Integer& x, const Integer& z)
{
	//(X^2 + Y^2)Z^2 = Z^4 + d*X^2*Y^2
	//	Y^2 * (Z^2 - d*X^2) = Z^4 - X^2*Z^2 
	//	Y^2 = (Z^4 - X^2*Z^2) * inv(Z^2 - d*X^2)
	//returns Y given X and Z
	//about 1 / 2 probability no corresponding y(? , 1 / 2 of numbers have no square root in prime finite field)
	
	//about same formula as the function below, simply swap all x and y references
	return Ed_proj_xrecover(x, z);
}
Integer Ed_proj_xrecover(const Integer& y, const Integer& z)
{
	//(X^2 + Y^2)Z^2 = Z^4 + d*X^2*Y^2
	//returns X given Y and Z
	//about 1 / 2 probability no corresponding x(? , 1 / 2 of numbers have no square root in prime finite field)
	
	Integer YY = ma.Square(y);
	Integer ZZ = ma.Square(z);

	Integer ZZZZ = ma.Square(ZZ);
	Integer ZZYY = ma.Multiply(ZZ, YY);
	Integer dYY = ma.Multiply(d, YY);

	//XX = (ZZ**2 - ZZ*YY)*inv(ZZ - Ed25519_d*YY) % Ed25519_m;
	Integer XXdenom = Ed_inv(ma.Subtract(ZZ, dYY));
	Integer ZZZZ_ZZYY = ma.Subtract(ZZZZ, ZZYY);
	Integer XX = ma.Multiply(ZZZZ_ZZYY, XXdenom);
	return Ed_sqrt(XX);
}

ECC_point randProjPoint()
{
	Integer x(m), y, z;
	while (x == m){
		y = Integer(rng, 0, m);
		z = Integer(rng, 0, m);
		x = Ed_proj_xrecover(y, z);
		//cout << "randProjPoint x: "<< x << endl;
		//cout << "randProjPoint y: " << y << endl;
		//cout << "randProjPoint z: " << z << endl;
	}
	return ECC_point(x, y, z);
}

ECC_point randAffPoint()
{
	Integer x(m), y;

	while (x == m) {
		y = Integer(rng, 0, m);
		x = Ed_xrecover(y);
		//cout << "randAffPoint x: " << x << endl;
		//cout << "randAffPoint x: " << y << endl;
	}
	return ECC_point(x, y);
}

ECC_point randPoint()
{
	int a = rng.GenerateBit();
	if (a == 0)
		return randProjPoint();
	else
		return randAffPoint();
}

bool is_Ed_point(ECC_point& a) {
	//verify this equation holds in the finite field of m:
	//	(X^2 + Y^2)Z^2 = Z^4 + d*X^2*Y^2
	Integer x = a.getX(), y = a.getY(), z = a.getZ();
	Integer XX = ma.Square(x);
	Integer YY = ma.Square(y);
	Integer ZZ = ma.Square(z);
	Integer XXplusYY = ma.Add(XX,YY);
	Integer ZZZZ = ma.Square(ZZ);
	Integer XXYY = ma.Multiply(XX, YY);
	Integer dXXYY = ma.Multiply(d, XXYY);
	
	Integer left = ma.Multiply(XXplusYY, ZZ);
	Integer right = ma.Add(ZZZZ,dXXYY);
	if (left != right) {
		cout << "ERROR, point is not an Ed25519 point \n" << a << endl;
	}
	return left == right;
}

void test_proj_aff_add_double(int n, bool display)
{
	//n: the number of loops
	//tests if add_points() and double_point() of Proj and Aff agree
	//tests if add_points() agrees with double_point()
	ECC_point testP;
	ECC_point testProjDouble, testProjAdd, testProjStaticDouble, testProjStaticAdd;
	ECC_point testAffDouble, testAffAdd;
	for (int i = 0; i < n; i++) {
		if (display)
			cout << "loop " << i << endl;
		testP = randPoint();

		testProjDouble = ECC_point(testP);
		testProjAdd = ECC_point(testP);
		testProjStaticDouble = ECC_point::double_point(&testProjDouble);
		testProjStaticAdd = ECC_point::add_points(&testProjAdd,testP);

		testAffDouble = ECC_point(testP);
		testAffAdd = ECC_point(testP);
		
		testProjDouble.double_point();
		testAffDouble.double_point_aff();
		testProjDouble.affRepr();

		testProjAdd.add_points(testP);
		testAffAdd.add_points_aff(testP);
		testProjAdd.affRepr();

		testProjStaticAdd.affRepr();
		testProjStaticDouble.affRepr();

		if (!(testProjDouble == testAffDouble)) 
			cout << "Doubling discrepancy between Aff and Proj\n";
		if (!(testProjAdd == testAffAdd))
			cout << "Adding discrepancy between Aff and Proj\n";

		if (!(testProjDouble == testProjAdd))
			cout << "Add-Doubling discrepancy in Proj\n";
		if (!(testAffDouble == testAffAdd))
			cout << "Add-Doubling discrepancy in Aff\n";
		if (!(testProjStaticDouble == testProjStaticAdd))
			cout << "Add-Doubling discrepancy in static Proj\n";

		bool pdpa = testProjDouble == testProjAdd;
		bool papsd = testProjAdd == testProjStaticDouble;
		bool psdpsa = testProjStaticDouble == testProjStaticAdd;
		if (pdpa && papsd && psdpsa) {
			if(display)
				cout << "If no other errors printed, all tests pass for this point.\n";
		}
		else
			cout << "You screwed up implementing ECC arithmetic.\n";

		if (display) {
			cout << "testP\n" << testP << endl;
			cout << "testProjDouble\n" << testProjDouble << endl;
			cout << "testProjAdd\n" << testProjAdd << endl;
			cout << "testProjStaticDouble\n" << testProjStaticDouble << endl;
			cout << "testProjStaticAdd\n" << testProjStaticAdd << endl;
			cout << "testAffDouble\n" << testAffDouble << endl;
			cout << "testAffAdd\n" << testAffAdd << endl;
		}

	}

}

void test_proj_aff_scale(int n, bool display)
{
	//n: the number of loops
	//tests if scale_point() of Proj and Aff, static and instance method, agree
	ECC_point testP;
	ECC_point testProj, testProjStatic;
	ECC_point testAff;
	Integer expo;
	//extern const Integer l;
	//extern const AffPoint* affZero;
	for (int i = 0; i < n; i++) {
		if(display)
			cout << "loop " << i << endl;
		testP = randPoint();
		is_Ed_point(testP);

		expo = Integer(rng, 0, l - 1);

		if (display) {
			cout << "Point to test:\n" << testP << endl;
			cout << "scalar: \n" << expo << endl;
		}

		testProjStatic = ECC_point::scale_point(expo, testP);
		is_Ed_point(testProjStatic);
		testProjStatic.affRepr();

		testProj = ECC_point(testP);
		is_Ed_point(testProj);
		testProj.scale_point(expo);
		testProj.affRepr();

		testAff = ECC_point(testP);
		testAff.scale_point_aff(expo);

		if (display) {
			cout << "testProj\n" << testProj << endl;
			cout << "testProjStatic \n" << testProjStatic << endl;
			cout << "testAff\n" << testAff << endl;
		}

		if (testProj != testAff)
			cout << "Scaling discrepancy between Aff and Proj\n";
		
		if (testProj == testProjStatic) {
			if (display)
				cout << "If no other errors printed, tests pass for this point.\n";
		}
		else
			cout << "You screwed up implementing ECC arithmetic.\n";
		/*
		//check that l*anypoint == affZero
		testProj.scale_point(l);
		testProj.affRepr();
		testAff.scale_point_aff(l);
		if ((testProj == testAff) && (testAff == projZero)) {
			if (display)
				cout << "All tests passed.\n";
		}
		else {
			cout << "Failed. l*(any point) doesn't result in affZero.\n";
			cout << "Original:\n" << testP << endl;
			cout << "Scaled Affine:\n" << testAff << endl;
			cout << "Scaled Proj:\n" << testProj << endl;
		}
		*/
	}
}

void test_scale_add(int n, bool display) {
	//n: the number of loops
	//tests if scale_point() and add_points() of Proj agree
	ECC_point testP;
	ECC_point testScale, testAdd;
	Integer expo;
	//extern const Integer l;
	//extern const AffPoint* affZero;
	for (int i = 0; i < n; i++) {
		if (display)
			cout << "loop " << i << endl;
		testP = randPoint();
		is_Ed_point(testP);

		expo = Integer(rng, 0, 100);

		if (display) {
			cout << "Point to test:\n" << testP << endl;
			cout << "scalar: \n" << expo << endl;
		}
		
		testScale = ECC_point(testP);
		is_Ed_point(testScale);
		testAdd = ECC_point(projZero);
		is_Ed_point(testAdd);
		
		testScale.scale_point(expo);
		testScale.affRepr();
		is_Ed_point(testScale);

		for (int i = 0; i < expo; i++) {
			testAdd.add_points(testP);
		}
		testAdd.affRepr();
		is_Ed_point(testAdd);

		if (!(testScale == testAdd)) {
			cout << "Discrepancy between Scale and Add\n";
			cout << "Scale:\n" << testScale << endl;
			cout << "Add:\n" << testAdd << endl;
		}
		else if (display) {
			cout << "You're fine.\n";
			cout << testAdd << endl;
		}

	}

}

void test_add_sub(int n, bool display)
{
	//n: the number of loops
	//test is add_points() and subtract_points() agree
	ECC_point testA, testB;
	for (int i = 0; i < n; i++) {
		if (display)
			cout << "loop " << i << endl;
		testA = randPoint();
		testB = randPoint();

		if (display) {
			cout << "testA:\n" << testA << endl;
			cout << "testB:\n" << testB << endl;
		}

		//test any point minus itself is zero
		if (projZero != ECC_point::subtract_points_aff(testA, testA))
			cout << "A - A != 0";
		if (projZero != ECC_point::subtract_points_aff(testB, testB))
			cout << "B - B != 0";

		//A + B - A = B
		ECC_point a_pb_a = testA.deepCopy();
		a_pb_a.add_points(testB);
		a_pb_a.subtract_points(testA);
		a_pb_a.affRepr();
		
		

		//2*B - B = B
		ECC_point b2_b = testB.deepCopy();
		b2_b.double_point();
		b2_b.subtract_points(testB);
		b2_b.affRepr();

		testA.affRepr();
		testB.affRepr();

		if (testB != a_pb_a)
			cout << "A+B-A != B\n";
		if (testB != b2_b)
			cout << "2*B-B != B\n";


	}
}
