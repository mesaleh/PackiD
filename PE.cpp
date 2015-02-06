/*
 * PE.cpp
 *
 *  Created on: January 1, 2015
 *  Author: Moustafa
 *  Version: 1.4
 *
 * TODO:
 * - Cache some intensive functions .
 * - Check rounding up and down for SizeOfRawData and PointerToRawData, respectively.
 */

#include <cmath>
#include <cstring>
#include <fstream>
#include <map>
#include <vector>
#include <utility>
#include <string>
#include <sstream>
#include "PE.h"
#include "Util.h"

#define EP_NOT_IN_SECTIONS	-1

#define IMAGE_FIRST_SECTION64(h) ((PIMAGE_SECTION_HEADER) ((DWORD)h+FIELD_OFFSET(IMAGE_NT_HEADERS64,OptionalHeader)+((PIMAGE_NT_HEADERS64)(h))->FileHeader.SizeOfOptionalHeader))

void PE::init()
{
	FileName			= NULL;
	//FileHandle 		= 0;
	LoadAddr	 		= NULL;

	FileSize			= 0;
	PEheader			= NULL;
	Suspicious			= 0;
	fImportByOrdinal	= false;
	DoneImportScaning	= false;
	DoneSectionParsing	= false;

	EpSection			= NULL;
}

PE::PE()
{
	init();
}

PE::~PE()
{
	unloadFile();
}

PE::PE(char* fname)
{
	init();
	FileName = fname;
}

/* Loads the file ONLY if it's a PE file */
LPVOID PE::loadPE(char* FileName)
{
	if(LoadAddr)
		unloadFile();

	LPVOID FH = loadFile(FileName);
	if(!FH)				return NULL;
	if(!isPE(FH))		return NULL;			// The file is not PE file

	/* Load PE info */

	// Get PE header offset
	PEheader = (PIMAGE_NT_HEADERS) getPEoffset();
	PEheader64 = (PIMAGE_NT_HEADERS64) getPEoffset();

	return PEheader;
}

LPVOID PE::loadFile(char* fn)
{
	FileName = fn;

	FileHandle.open(FileName, ios::in | ios::binary | ios::ate);
	if(!FileHandle.is_open())				return NULL;

	FileSize = (unsigned int) FileHandle.tellg();
	if(FileSize == INVALID_FILE_SIZE)		return NULL;

	LoadAddr = (LPBYTE) new char [FileSize];
    FileHandle.seekg (0, ios::beg);
    FileHandle.read ((char *)LoadAddr, FileSize);
    FileHandle.close();

	return LoadAddr;
}

bool PE::isPE(LPVOID FileHandle)
{
	if(FileHandle == NULL) return false;

	if(*(WORD *)LoadAddr != 0x5A4D)	return false;		// test for 'MZ'

	// get PE header
	DWORD *sig = (DWORD *) getPEoffset();

	if(*sig == 0x00004550)	return true;					// test for 'PE\0\0'

	return false;
}

void PE::unloadFile()
{
	if(LoadAddr) {
		delete LoadAddr;
		LoadAddr = NULL;
	}
}

void PE::unloadPE()
{
	unloadFile();
}

DWORD PE::getPEoffset()
{
	unsigned int index = *(int *) ((char *)LoadAddr + 0x3C);
	if(index >= FileSize)	return 0;

	char *handle = (char *)LoadAddr;
	DWORD *sig = (DWORD *)&handle[index];

	return (DWORD) sig;
}

// get RVA of EP
DWORD PE::getEntryPoint()
{
	if(isPE64())
		return PEheader64->OptionalHeader.AddressOfEntryPoint;
	
	return PEheader->OptionalHeader.AddressOfEntryPoint;			
	
}

PIMAGE_SECTION_HEADER PE::getFirstSection()
{
	PIMAGE_SECTION_HEADER Section;

	if(isPE64())
		Section = IMAGE_FIRST_SECTION64(PEheader);
	else
		Section = IMAGE_FIRST_SECTION(PEheader);

	return Section;
}

/* get the sections pointed by entry point, that is,
 * the first to be executed regardless it's .text/CODE or not
 * */
PIMAGE_SECTION_HEADER PE::getExecSection()
{	
	// return it if we already got it.
	if(EpSection)	return EpSection;

	// get entry point
	unsigned int EP, NumberOfSections;
	PIMAGE_SECTION_HEADER Section;

	if(isPE64()) {
		EP = PEheader64->OptionalHeader.AddressOfEntryPoint;		// get RVA of EP
		Section = IMAGE_FIRST_SECTION64(PEheader);
		NumberOfSections = PEheader64->FileHeader.NumberOfSections;
	}
	else {
		EP = PEheader->OptionalHeader.AddressOfEntryPoint;			// get RVA of EP
		Section = IMAGE_FIRST_SECTION(PEheader);
		NumberOfSections = PEheader->FileHeader.NumberOfSections;
	}

	// check which section EP is pointing to
	for (unsigned int i = 0; i < NumberOfSections; i++, Section++)
	{
		if ((EP >= Section->VirtualAddress) && (EP < Section->VirtualAddress+Section->Misc.VirtualSize))
		{
			if((strncmp((char *)Section->Name, ".text", IMAGE_SIZEOF_SHORT_NAME) != 0) && \
				(strncmp((char *)Section->Name, "CODE", IMAGE_SIZEOF_SHORT_NAME) != 0) )
					Suspicious |= EXEC_SECTION_IS_NOT_TEXT;

			// check bounds
			if(Section->PointerToRawData + Section->SizeOfRawData > FileSize)		Suspicious |= SECTION_OUTOFBOUND;

			EpSection = Section;
			return Section;
		}
	}

	return NULL;
}


/* get the sections that contains the address RVA
 * */
PIMAGE_SECTION_HEADER PE::getSection(DWORD RVA)
{
	unsigned int NumberOfSections;
	PIMAGE_SECTION_HEADER Section;

	if(isPE64()) {
		Section = IMAGE_FIRST_SECTION64(PEheader);
		NumberOfSections = PEheader64->FileHeader.NumberOfSections;
	}
	else {
		Section = IMAGE_FIRST_SECTION(PEheader);
		NumberOfSections = PEheader64->FileHeader.NumberOfSections;
	}

	// check which section EP is pointing to
	for (unsigned int i = 0; i < NumberOfSections; i++, Section++)
	{
		if ((RVA >= Section->VirtualAddress) && (RVA < Section->VirtualAddress+Section->Misc.VirtualSize))
			return Section;
	}

	return NULL;
}

// can be used by both 32 and 64 bit executables
bool PE::isDLL()
{
	if(PEheader->FileHeader.Characteristics & IMAGE_FILE_DLL)
		return true;
	return false;
}

bool PE::isPE64()
{
	if(PEheader64->OptionalHeader.Magic == 0x20B)	return true;			// 64 bit file
	return false;
}

template <class T>		// T: PIMAGE_THUNK_DATA64 or PIMAGE_THUNK_DATA32
vector<string> PE::getModuleAPIs(T pThunk, PIMAGE_SECTION_HEADER IT)
{
	vector<string> APIs;

	if( ((DWORD)pThunk < ((DWORD)LoadAddr + IT->PointerToRawData)) || ((DWORD)pThunk > ((DWORD)LoadAddr + IT->PointerToRawData + IT->SizeOfRawData)) ) {
		Suspicious |= CORRUPTED_IMPORTS;
		return APIs;
	}	
	
	ULONGLONG iIMAGE_ORDINAL_FLAG;
	if(isPE64())
		iIMAGE_ORDINAL_FLAG = IMAGE_ORDINAL_FLAG64;
	else
		iIMAGE_ORDINAL_FLAG = IMAGE_ORDINAL_FLAG32;

	if(pThunk->u1.Ordinal & iIMAGE_ORDINAL_FLAG)	fImportByOrdinal = true;	

	// if import by name only not ordinal
	while(pThunk->u1.Ordinal)
	{
		string API;

		// if import by name
		if(!(pThunk->u1.Ordinal & iIMAGE_ORDINAL_FLAG)) {
			PIMAGE_IMPORT_BY_NAME pStr = (PIMAGE_IMPORT_BY_NAME)((DWORD) LoadAddr + pThunk->u1.AddressOfData - IT->VirtualAddress+IT->PointerToRawData);
			if( ((DWORD)pStr < ((DWORD)LoadAddr + IT->PointerToRawData)) || ((DWORD)pStr > ((DWORD)LoadAddr + IT->PointerToRawData + IT->SizeOfRawData)) ) {
				Suspicious |= CORRUPTED_IMPORTS;
				return APIs;
			}
			API = (char*)(pStr->Name);
		}
		// else if import by ordinal
		else {
			int n = pThunk->u1.Ordinal & 0x00FF;		// get ordinal number
			API = "Ord(" + numToStr(n) + ")";
		}
		
		APIs.push_back(API);
		pThunk++;
	}

	return APIs;
}

vector<Module> PE::getImports()
{
	unsigned int ImportOffset;
	unsigned int ImportSize;

	if(isPE64()) {
		ImportOffset = PEheader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
		ImportSize = PEheader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
	}
	else {
		ImportOffset = PEheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
		ImportSize = PEheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
	}

	
	if(ImportOffset == 0 && ImportSize == 0) {
		Suspicious |= NO_IMPORTS;
		return Modules;		// no imports
	}

	if(ImportOffset == 0 || ImportSize == 0) {
		Suspicious |= CORRUPTED_IMPORTS;
		return Modules;		// no imports
	}

	if(ImportSize > FileSize) {
		Suspicious |= CORRUPTED_IMPORTS;
		return Modules;		// no imports
	}

	PIMAGE_SECTION_HEADER IT;
	IT = getSection(ImportOffset);

	
	if( !IT || (IT->SizeOfRawData < ImportSize) || (IT->PointerToRawData + IT->SizeOfRawData) >  FileSize )	{
		Suspicious |= CORRUPTED_IMPORTS;
		return Modules;
	}

	PIMAGE_IMPORT_DESCRIPTOR  imd = (PIMAGE_IMPORT_DESCRIPTOR) (LoadAddr + ImportOffset - IT->VirtualAddress + IT->PointerToRawData );
		
	if( ((DWORD)imd < ((DWORD)LoadAddr + IT->PointerToRawData)) || ((DWORD)imd > ((DWORD)LoadAddr + IT->PointerToRawData + IT->SizeOfRawData)) ) {
		Suspicious |= CORRUPTED_IMPORTS;
		return Modules;
	}		

	if(imd == 0 || imd->Name == 0 || imd->Characteristics == 0)
	{
		Suspicious |= CORRUPTED_IMPORTS;
		return Modules;
	}
	
	// get modules
	while(imd != 0 && imd->Name != 0 && imd->Characteristics != 0) {

		// within section ?
		if( (imd->Name < IT->VirtualAddress) || (imd->Name > (IT->VirtualAddress + IT->SizeOfRawData)) ) {
			Suspicious |= CORRUPTED_IMPORTS;
			return Modules;
		}

		DWORD ModuleNameAddr = (DWORD) ((DWORD)LoadAddr + imd->Name - IT->VirtualAddress + IT->PointerToRawData );

		// check that name ends within region 
		DWORD i = (DWORD) (imd->Name - IT->VirtualAddress + IT->PointerToRawData);
		while(LoadAddr[i] != 0 && i < (IT->PointerToRawData + IT->SizeOfRawData))	i++;
		if(i >= (IT->PointerToRawData + IT->SizeOfRawData)) {
			Suspicious |= CORRUPTED_IMPORTS;
			return Modules;
		}
		// end name checking

		Module mod;
		mod.name = (char*) ModuleNameAddr;

		// check if valid length
		if(mod.name.length() == 0) {
			Suspicious |= CORRUPTED_IMPORTS;
			//return ModulesAPIs;
		}

		vector<string> APIs;
		// get APIs inside each module
		if(isPE64()) {
			PIMAGE_THUNK_DATA64 pThunk = (PIMAGE_THUNK_DATA64) (LoadAddr + imd->Characteristics - IT->VirtualAddress + IT->PointerToRawData );
			APIs = getModuleAPIs(pThunk, IT);			
		}
		else {
			PIMAGE_THUNK_DATA32 pThunk = (PIMAGE_THUNK_DATA32) (LoadAddr + imd->Characteristics - IT->VirtualAddress + IT->PointerToRawData );
			APIs = getModuleAPIs(pThunk, IT);	
		}
		
		mod.APIs = APIs;
		Modules.push_back(mod);

		imd++;
	}

	return Modules;
}

bool PE::isImportByOrdinal()
{
	if(!DoneImportScaning)
		getImports();
	return fImportByOrdinal;
}

vector<PIMAGE_SECTION_HEADER> PE::getSections()
{
	if(DoneSectionParsing)	return Sections;

	// get entry point
	unsigned int EP, NumberOfSections;
	PIMAGE_SECTION_HEADER Section;

	if(isPE64()) {
		EP = PEheader64->OptionalHeader.AddressOfEntryPoint;		// get RVA of EP
		Section = IMAGE_FIRST_SECTION64(PEheader);
		NumberOfSections = PEheader64->FileHeader.NumberOfSections;
	}
	else {
		EP = PEheader->OptionalHeader.AddressOfEntryPoint;			// get RVA of EP
		Section = IMAGE_FIRST_SECTION(PEheader);
		NumberOfSections = PEheader->FileHeader.NumberOfSections;
	}

	for (unsigned int i = 0; i < NumberOfSections; i++, Section++)
	{		
		Sections.push_back(Section);

		// if it's EP section
		if ((EP >= Section->VirtualAddress) && (EP < Section->VirtualAddress+Section->Misc.VirtualSize))
		{
			if((strncmp((char *)Section->Name, ".text", IMAGE_SIZEOF_SHORT_NAME) != 0) && \
				(strncmp((char *)Section->Name, "CODE", IMAGE_SIZEOF_SHORT_NAME) != 0) )
					Suspicious |= EXEC_SECTION_IS_NOT_TEXT;

			// check bounds
			if(Section->PointerToRawData + Section->SizeOfRawData > FileSize)	Suspicious |= SECTION_OUTOFBOUND;	
			EpSection = Section;
		}
	}
	
	DoneSectionParsing = true;
	return Sections;
}

// ##### File's derived information #############

float getEntropy(LPVOID Mem, INT Size)
{
	if(Size == 0)	return -1;

	UINT SymbolsCount[256];
	float Entropy = 0;

	for(int i = 0; i < 256; i++)
		SymbolsCount[i] = 0;

	for(int i = 0; i < Size; i++) 
		SymbolsCount[ *((BYTE*)((UINT)Mem+i)) ]++;
	
	float p;
	for(int i = 0; i < 256; i++) {
		p = ((float)SymbolsCount[i] / (float)Size);
		if(p > 0.0)	
			Entropy = Entropy - p * (float) (log(p) / log(2));
	}

	return Entropy;
}

float PE::getFileEntropy()
{
	if(!LoadAddr)	return -1;

	return getEntropy(LoadAddr, FileSize);
}

float PE::getSectionEntropy(PIMAGE_SECTION_HEADER Section)
{
	if(!LoadAddr || !Section)	return -1;

	LPVOID Addr = 0;

	if( (Section->PointerToRawData > FileSize)	|| 
		(Section->SizeOfRawData > FileSize)		|| 
		(Section->PointerToRawData + Section->SizeOfRawData > FileSize)) {
			Suspicious |= SECTION_OUTOFBOUND;
			return -2;
	}

	Addr = LoadAddr + Section->PointerToRawData;
	DWORD Size = Section->SizeOfRawData;
	if(Size == 0)	return -3;

	return getEntropy(Addr, Size);
}
