#include "stdafx.h"
#include "GCircuit.h"


GCircuit::GCircuit()
{
}


GCircuit::~GCircuit()
{
}

GCircuitT::GCircuitT(function<pair<ECC_point, SecByteBlock>> ttilda, int security, bool triv)
{
	trivial = triv;
	lab = Label(security,triv);
}
