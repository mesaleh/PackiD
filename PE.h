/*
 * PE.h
 *
 *  Created on: January 1, 2015
 *  Author: Moustafa
 *  Version: 1.4
 *
 */

#ifndef _PE_
#define _PE_


// Suspicious flags, it's 8 flags set if PE file exhibits suspicious features
#define	EXEC_SECTION_IS_NOT_TEXT	0x01		// if the section pointed to by entry point is not .text or CODE
#define NO_IMPORTS					0x02
#define CORRUPTED_IMPORTS			0X04
#define SECTION_OUTOFBOUND			0X08		// Section size passes file size

#include <iostream>
#include <fstream>
#include <vector>
#ifndef __linux__
	#include <windows.h>
#else
	#include "Typedef.h"
#endif

using namespace std;
typedef vector<pair<string, vector<string> > >	ArrStrArr;		// Array of strings to arrays
typedef vector<pair<string, string> >			ArrDict;		// Array of dicationary
typedef vector<vector<pair<string, string> > >	ArrArrDict;		// Array of array of dictionary

typedef struct
	{
		string				name;
		vector<string>		APIs;
	} Module;

class PE
{
private:
	template <class T>		// T: PIMAGE_THUNK_DATA64 or PIMAGE_THUNK_DATA32
	vector<string> getModuleAPIs(T pThunk, PIMAGE_SECTION_HEADER IT);

	//==== cached elements. Used to avoid recalculating parts of the PE ===//
	PIMAGE_SECTION_HEADER	EpSection;

public:
	char*				FileName;
	ifstream			FileHandle;
	LPBYTE				LoadAddr;				// address of where the file loaded in memory now
	DWORD		FileSize;

												// so other functions use it directly without loading it.
	PIMAGE_NT_HEADERS	PEheader;
	PIMAGE_NT_HEADERS64	PEheader64;
	char 				Suspicious;				// group of flags set if any suspicious sysmptoms noticed in PE structure
	bool				fImportByOrdinal;		// flag is set if the file does any import by ordinal
	vector<Module>		Modules;				// an array that holds imported modules structs
	vector<PIMAGE_SECTION_HEADER> Sections;		// an array that contains sections info
	bool				DoneImportScaning;		// set if import scanning is done
	bool				DoneSectionParsing;		// set if section parsing is done

	PE();
	~PE();

	PE(char* FileName);

	void init();

	LPVOID loadPE()		{ return loadPE(FileName); }
	LPVOID loadPE(char* FileName);

	LPVOID loadFile()		{ return loadPE(FileName); }
	LPVOID loadFile(char* FileName);

	void unloadFile();

	void unloadPE();

	DWORD getPEoffset();

	DWORD getEntryPoint();

	PIMAGE_SECTION_HEADER getFirstSection();

	PIMAGE_SECTION_HEADER getExecSection();

	PIMAGE_SECTION_HEADER getSection(DWORD RVA);

	vector<PIMAGE_SECTION_HEADER> getSections();

	vector<Module> getImports();

	//-------- checks (boolean functions) -----------

	bool isPE(LPVOID FileHandle);

	bool isDLL();

	bool isPE64();

	bool isImportByOrdinal();

	//-------- extras ------------

	float getFileEntropy();

	float getSectionEntropy(PIMAGE_SECTION_HEADER Section);

	inline DWORD getSectionExactSize(PIMAGE_SECTION_HEADER Section)
	{
		if(Section->SizeOfRawData > Section->Misc.VirtualSize)
			return Section->Misc.VirtualSize;
		else
			return Section->SizeOfRawData;
	}


};



#endif
