/*
 * PackiD.cpp
 *
 *  Author: Moustafa Saleh
 *  Email: msaleh83@gmail.com
 */



#include <fstream>
#include <exception>
#include <algorithm>
#include "PE.h"
#include "PackiD.h"
#include "Util.h"

void PackiD::init()
{
	SigSize = 0;
	DbLoaded = false;
	Mode = MODE_DEEP;
	Signatures.reserve(EXPECTED_NUM_OF_SIGS);		// expected number of signatures, apprx.
}

PackiD::PackiD()
{
	init();
}

PackiD::PackiD(char* db_file)
{
	init();
	loadDB(db_file);
}

// remove spaces and preprocess the signature
void PackiD::preprocessSignature(string s, Signature *sig)
{
	string s2;
	BYTE wbyte = 0;
	BYTE sbyte = 0;
	map<char, unsigned char> Char2Num;
	Char2Num['0'] = 0x00;
	Char2Num['1'] = 0x01;
	Char2Num['2'] = 0x02;
	Char2Num['3'] = 0x03;
	Char2Num['4'] = 0x04;
	Char2Num['5'] = 0x05;
	Char2Num['6'] = 0x06;
	Char2Num['7'] = 0x07;
	Char2Num['8'] = 0x08;
	Char2Num['9'] = 0x09;
	Char2Num['A'] = 0x0A;
	Char2Num['B'] = 0x0B;
	Char2Num['C'] = 0x0C;
	Char2Num['D'] = 0x0D;
	Char2Num['E'] = 0x0E;
	Char2Num['F'] = 0x0F;

	//step1 --- convert every two characters to one byte, and convert every '?' to F and mark the wildcard in WildCardMap
	for(unsigned int i = 0; i < s.length(); i++)
	{
		if(isspace(s[i]))
			continue;

		wbyte = 0;
		sbyte = 0;

		for(int j = 0; j < 2; j++)
		{
			sbyte = sbyte << 4;
			wbyte = wbyte << 4;			

			if(((i + j) < s.length()) && !isspace(s[i+j]) && (s[i+j] != '?')) {
				sbyte |= Char2Num[s[i+j]];
				wbyte &= 0xF0;
			}
			else
			{
				// half nibble wildcard or, space at the end of file treated as '?'
				sbyte |= 0x0F;
				wbyte |= 0x0F;
			}
		}

		i++;

		sig->SignatureValues.push_back(sbyte);
		sig->SignatureWildCards.push_back(wbyte);
	}	
}


bool PackiD::loadDB(char* FileName)
{
	// ---- Open File ---------- //

	ifstream FileHandle;
	FileHandle.open(FileName, std::ifstream::binary);
	if(!FileHandle.is_open())				return false;

	FileHandle.seekg (0,FileHandle.end);
	UINT FileSize = (unsigned int) FileHandle.tellg();
	if(FileSize == INVALID_FILE_SIZE)		return false;

	LPBYTE LoadAddr = (LPBYTE) new char [FileSize];
	LPBYTE mp = LoadAddr;									// memory pointer, will move when reading strings from memory.
    FileHandle.seekg (0, ios::beg);
    FileHandle.read ((char *)LoadAddr, FileSize);
    FileHandle.close();

	// ---- Load DB ---- //
	bool failure = false;
	char* cLine = 0;
	DWORD LineSize = 0;
	char* BoundAddr = (char*)((DWORD)LoadAddr + FileSize);
	int i = 0;
	while(((DWORD)mp < (DWORD)BoundAddr) && !failure)
	{		
		//cout << i++ << '\r';
		string Line = getLineFromMem((LPVOID &)mp, BoundAddr);
			
		LineSize = Line.length();
		Line = trim(Line);		

		// skip empty lines or comment
		if(Line.length() == 0 || Line[0] == ';')
			continue;
		
		Signature signat;

		// get tool name
		signat.Tool = Line;
		
		// get signature		
		Line = getLineFromMem((LPVOID &)mp, BoundAddr);
		Line = trim(Line);

		// skip empty lines or comment
		if(Line.length() == 0 || Line[0] == ';')
			continue;

		if(Line.find(SIGFIELD) != 0) {
			//cout << "Error parsing database!";
			failure = true;
		}

		preprocessSignature(Line.substr(SIGFIELD_LEN), &signat);
		
		// get scanning location
		Line = getLineFromMem((LPVOID &)mp, BoundAddr);
		Line = trim(Line);
		
		if(Line == "ep_only = true")
			signat.isEP = true;
		else if(Line == "ep_only = false")
			signat.isEP = false;
		else
			failure = true;

		Signatures.push_back(signat);
	}
	delete[] LoadAddr;
	Signatures.shrink_to_fit();

	if(failure)	return false;
	DbLoaded = true;
	
	return true;

}


string PackiD::scanPE(PE &P)
{
	DWORD EPSizeOfRawData;
	DWORD EPVirtualAddress;
	DWORD EPPointerToRawData;
	DWORD FileSize, oFileSize, SizeOfHeaders;
	string result = NO_MATCH;						// default value if no match found
	LPBYTE EPAddr, SecAddr, oLoadAddr, LoadAddr;

	// get FileAlignment
	DWORD FileAlignment;
	if(P.isPE64()) {
		FileAlignment = P.PEheader64->OptionalHeader.FileAlignment;
		SizeOfHeaders = P.PEheader64->OptionalHeader.SizeOfHeaders;
	} else {
		FileAlignment = P.PEheader->OptionalHeader.FileAlignment;
		SizeOfHeaders = P.PEheader->OptionalHeader.SizeOfHeaders;
	}

	// entry point is in header
	if(P.getExecSection() == NULL) {
		if(P.getEntryPoint() > P.FileSize)	return result;

		EPSizeOfRawData = P.FileSize - P.getEntryPoint();
		if(Mode == MODE_HARDCORE || SizeOfHeaders > P.FileSize)
			oFileSize = P.FileSize;
		else 
			oFileSize = SizeOfHeaders;
		oLoadAddr = P.LoadAddr;
		EPAddr = P.LoadAddr + P.getEntryPoint();
	}
	else {
		// round up SizeOfRawData
		EPSizeOfRawData = roundUp(P.getExecSection()->SizeOfRawData, FileAlignment);
		EPSizeOfRawData = min(P.getExecSection()->Misc.VirtualSize, EPSizeOfRawData);

		// round down PointerToRawData to nearest FileAlignment		
		EPPointerToRawData = roundDown(P.getExecSection()->PointerToRawData, FileAlignment);
		EPVirtualAddress = P.getExecSection()->VirtualAddress;

		// not a valid pe
		if( (EPPointerToRawData > P.FileSize) || 
			(P.getEntryPoint() - EPVirtualAddress > EPSizeOfRawData) || 
			(P.getEntryPoint() - EPVirtualAddress > P.FileSize) ||
			(P.getEntryPoint() - EPVirtualAddress) + EPPointerToRawData > P.FileSize
			)
			return result;

		if( (EPSizeOfRawData > P.FileSize) || (EPPointerToRawData + EPSizeOfRawData > P.FileSize) )
			EPSizeOfRawData = P.FileSize - EPPointerToRawData;

		EPAddr = P.LoadAddr + (P.getEntryPoint() - EPVirtualAddress) + EPPointerToRawData;

		// scan the whole file with signatures that have ep_only = false
		if(Mode == MODE_HARDCORE)
		{
			oFileSize = P.FileSize;
			oLoadAddr = P.LoadAddr;
		}
		else
		{			
			oFileSize = EPSizeOfRawData;
			SecAddr = P.LoadAddr + EPPointerToRawData;

			if(Mode == MODE_DEEP) {
				oFileSize = EPSizeOfRawData;
				oLoadAddr = SecAddr;										// scan the whole section of entry point with signatures that have ep_oly = false
			}
			else {															// MODE_NORMAL
				oLoadAddr = EPAddr;
			}

		}
	}
		

	for(unsigned int k = 0; k < Signatures.size(); k++)
	{
		//cout << "Checking " << Signatures[k].Tool << endl;
		SigSize = Signatures[k].SignatureValues.size();

		// Even if current mode is MODE_HARDCORE, if the signature set to ep_only=true, scan only the ep. Other that that, follow the mode.
		if(Signatures[k].isEP || Mode == MODE_NORMAL)	{									
			FileSize = SigSize;
			LoadAddr = EPAddr;
		}
		else {
			FileSize = oFileSize;
			LoadAddr = oLoadAddr;
		}

		if(SigSize > FileSize)	continue;

		CHUNK* tbyte = (CHUNK *) LoadAddr;
		CHUNK* sbyte = (CHUNK*) Signatures[k].SignatureValues.data();
		CHUNK* wbyte = (CHUNK*) Signatures[k].SignatureWildCards.data();

		for(unsigned int i = 0; (i + SigSize - 1) < FileSize; i++)
		{
			tbyte = (CHUNK*) ((DWORD)LoadAddr + i);
			bool match = true;

			// loop over part of the file equal to signature 
			unsigned int j = 0;
			for(; j < (SigSize/sizeof(CHUNK)) && match; j++)
			{
				// if no match in case or the byte has no wildcard, or has wc at right, or left.
				
				if( (wbyte[j] | tbyte[j]) != sbyte[j] )
				{	
					match = false;
				}

				//else treat it as match
			}

			// check the rest of unaligned signature, byte by byte
			j = j * sizeof(CHUNK);
			if(j < (SigSize) && match)
			{
				while(j < SigSize && match) {
					if( (BYTE)(*((char*)wbyte+j) | *((char*)tbyte+j)) != (BYTE)*((char*)sbyte+j) )
					{	
						match = false;
					
					}
					j++;
				}
			}

			if(match)	{
				return Signatures[k].Tool;
			}
			// else shift to the right
			
		}
	}
	return result;
}

