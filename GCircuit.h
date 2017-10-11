#pragma once
#include "Chameleon.h"
#include "IBEhelpers.h"
using namespace std;
class GCircuitT
{
	bool trivial;
	function<pair<ECC_point, SecByteBlock>> Ttilda;
	Label lab;
public:
	GCircuitT(function<pair<ECC_point, SecByteBlock>> ttilda, int security);
	//~GCircuitT();
};

class GCircuitP
{
public:
	GCircuitP();
	~GCircuitP();
};