/*
 * PackiD.h
 *
 *  Author: Moustafa Saleh
 *  Email: msaleh83@gmail.com
 *
 */

#ifndef _PackiD_
#define _PackiD_

#include <vector>
#include <map>
#include <cstring>
#include "headers/PE.h"

struct Signature
{
	string							Tool;
	vector<BYTE>					SignatureValues;
	vector<BYTE>					SignatureWildCards;
	bool							isEP;
};

#define CHUNK			unsigned int

#define NO_MATCH		"NONE"
#define EXPECTED_NUM_OF_SIGS	4444			// This is just "expected" number of signature, it could be more or less. To save allocation time in vector

#define SIGFIELD		"signature = "
#define SIGFIELD_LEN	sizeof(SIGFIELD) - 1	// minus 1 because sizeof() counts null

#define WC_BYTE_VAL		256						// a value in IndexMap to indicate a place of a wildcard

#define MODE_NORMAL		0						// Scan only with signatures with ep_only = true, only at the ep
#define MODE_DEEP		1						// Normal mode + use signatures with ep_only = false to scan with them the whole section of the ep
#define MODE_HARDCORE	2						// Normal mode + use signatures with ep_only = false to scan with them the entire file


class PackiD {

private:

	vector<Signature> Signatures;
	DWORD SigSize;
	int Mode;								// scanning mode
	bool DbLoaded;
	
	void init();

	// preprocess the signature for fast scanning afterwards
	void preprocessSignature(string s, Signature* sig);		

public:
	PackiD();
	PackiD(char* db_file);

	inline void setMode(int mode) {
		if(mode >= MODE_NORMAL && mode <= MODE_HARDCORE)
			Mode = mode;
		else Mode = MODE_NORMAL;
	}

	inline bool isDbLoaded() {
		return DbLoaded;
	}

	string scanPE(PE &P);
	bool loadDB(char* FileName);

};


#endif
