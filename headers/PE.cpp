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


DWORD PE::getOffsetFromRva(DWORD rva)
{
	/*	When translating RVA to physical offset, RVA is valid if it was within the image, that is, the start of the MZ header until the end of the last section's SizeOfRawData.
		If RVA was in the overlay (padding) of the physical file, or within the VirtualSize of the section but outside the SizeOfRawData, then it should be invalid.
	*/
	PIMAGE_SECTION_HEADER Section;
	if (Section = getSection(rva)) {
		// we could get a containing section, but still the rva outside the physical file in case of VirtualSize > SizeOfRawData
		// so we need to check if rva > FileSize
		rva = rva - Section->VirtualAddress + Section->PointerToRawData;
		if (rva > FileSize)	return -1;
		return rva;
	}

	// if the file has no sections or the rva in the header
	Section = getFirstSection();
	if (!Section || rva < Section->VirtualAddress)	return rva;

	return -1;
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

	if(*(WORD *)LoadAddr != 0x5A4D)	return false;			// test for 'MZ'

	// get PE header
	DWORD *sig = (DWORD *) getPEoffset();

	if(*sig == 0x00004550)	return true;					// test for 'PE\0\0'

	return false;
}

void PE::unloadFile()
{
	if(LoadAddr) {
		delete[] LoadAddr;
		LoadAddr = NULL;
	}
}

void PE::unloadPE()
{
	unloadFile();
}

DWORD PE::getPEoffset()
{
	/*
	// consider rewrite it as:
	IMAGE_DOS_HEADER* pidh = (IMAGE_DOS_HEADER*)LoadAddr;
    IMAGE_NT_HEADERS* pinh = (IMAGE_NT_HEADERS*)((ULONG_PTR)(LoadAddr)+pidh->e_lfanew);

	*/

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
		if ((RVA >= Section->VirtualAddress) && ( RVA < Section->VirtualAddress + max(Section->Misc.VirtualSize, Section->SizeOfRawData) ))
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

	// check if IMAGE_THUNK_DATA is within the section of Import directory, otherwise, most likely the file is packed or manualy manipulated.
	if (((DWORD)pThunk < ((DWORD)LoadAddr + IT->PointerToRawData)) || ((DWORD)pThunk >((DWORD)LoadAddr + IT->PointerToRawData + IT->SizeOfRawData))) {
		Suspicious |= SUSPICIOUS_IMPORTS;
	}

	// check if IMAGE_THUNK_DATA points out of file boundaries.
	if (((DWORD)pThunk < ((DWORD)LoadAddr)) || ( ((DWORD)pThunk + sizeof(*pThunk)) > ((DWORD)LoadAddr + FileSize)) ) {
		Suspicious |= CORRUPTED_IMPORTS;
		return APIs;
	}

	ULONGLONG iIMAGE_ORDINAL_FLAG;
	if(isPE64())
		iIMAGE_ORDINAL_FLAG = IMAGE_ORDINAL_FLAG64;
	else
		iIMAGE_ORDINAL_FLAG = IMAGE_ORDINAL_FLAG32;

	if(pThunk->u1.Ordinal & iIMAGE_ORDINAL_FLAG)	fImportByOrdinal = true;	
		
	while(pThunk->u1.Ordinal)
	{
		string API;

		// if import by name
		if(!(pThunk->u1.Ordinal & iIMAGE_ORDINAL_FLAG)) {
			// Yup, ApiNameOffset is DWORD, 32bit, for both 32bit and 64bit executables, assuming we've not yet seen an 64bit executable > 4GB.
			DWORD ApiNameOffset = getOffsetFromRva(pThunk->u1.AddressOfData) + FIELD_OFFSET(IMAGE_IMPORT_BY_NAME, Name);

			// within file boundaries ?
			if (ApiNameOffset > FileSize) {
				Suspicious |= CORRUPTED_IMPORTS;
			}
			else {
				DWORD i = ApiNameOffset;
				while (i < FileSize && LoadAddr[i] != 0 && (i - ApiNameOffset < MAX_API_NAME)) i++;	// There is no unallowed chars for API name.	
				/*
				* There are three cases here:
				* 
				* 1- If the size = MAX_API_NAME, Win loader's RtlInitString() will take the first MAX_API_NAME name regardless of the "real" size. That would be the API that will be looked for.
				* 2- If the Name was shorter that MAX_API_NAME but passes the file size, most likely the memory location at the offset "file size"
				* will be 0, so the loader will read the zero and terminates the string. 
				* Unless in very rare condition that the file ends exactly at the boundary of a memory page and accessing next page will fire an exception.
				* For those two cases, we'll get the string up until the boundary, MAX_API_NAME or FileSize.
				* 3- The file we're scanning is a good file that respects itself and has a normal API name, which is a case we don't usually encounter when dealing with malware :)
				*/
				if ((i >= FileSize) || (i - ApiNameOffset >= MAX_API_NAME))
					Suspicious |= SUSPICIOUS_IMPORTS;
				
				API = string((char*) &LoadAddr[ApiNameOffset], i - ApiNameOffset);
			}
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
		Suspicious |= SUSPICIOUS_IMPORTS;
	}

	// outside the file boundaries
	if (((DWORD)imd < ((DWORD)LoadAddr)) || ( ((DWORD)imd + sizeof(IMAGE_IMPORT_DESCRIPTOR)) >((DWORD)LoadAddr + FileSize))) {
		Suspicious |= CORRUPTED_IMPORTS;
		return Modules;
	}

	// some files compiled with Borland compiler have imd->Characteristics = 0.
	if ((signed)imd->Characteristics <= 0 && imd->FirstThunk != 0)	imd->Characteristics = imd->FirstThunk;

	if (imd == 0 || imd->Name == 0 || (signed)imd->Characteristics <= 0)
	{
		Suspicious |= CORRUPTED_IMPORTS;
		return Modules;
	}
	
	// get modules
	while (imd != 0 && imd->Name != 0 && imd->FirstThunk != 0) {
		
		// within section ?
		if( (imd->Name < IT->VirtualAddress) || (imd->Name > (IT->VirtualAddress + IT->SizeOfRawData)) ) {
			Suspicious |= SUSPICIOUS_IMPORTS;
		}

		DWORD ModuleNameOffset = getOffsetFromRva(imd->Name);
		Module mod;

		// within file boundaries ?
		if (ModuleNameOffset >= FileSize) {
			Suspicious |= CORRUPTED_IMPORTS;
		}
		else {
			// check that name ends within region 
			DWORD i = ModuleNameOffset;
			/*	Tip: why not just checking for zero at the end of string? Because if the last non null char of the string was the last byte in the file.
				windows loader will consider the name valid and load the module. Check fbd90df9cc16cc5b2b24271dfb5bb9e7aad950ccd72c154804b286ebc5b8e21d as example
			*/
			while (i < FileSize && LoadAddr[i] != 0 && (i - ModuleNameOffset < MAX_API_NAME)) i++;
			if ((i >= FileSize) || (i - ModuleNameOffset >= MAX_PATH))
				Suspicious |= SUSPICIOUS_IMPORTS;

			mod.name = string((char*)&LoadAddr[ModuleNameOffset], i - ModuleNameOffset);
		}
		// end name checking

		vector<string> APIs;
		// check if valid length
		if(mod.name.length() == 0) {
			Suspicious |= CORRUPTED_IMPORTS;
		}
		else {			
			// get APIs inside each module
			if(isPE64()) {
				PIMAGE_THUNK_DATA64 pThunk = (PIMAGE_THUNK_DATA64) (LoadAddr + imd->Characteristics - IT->VirtualAddress + IT->PointerToRawData );
				APIs = getModuleAPIs(pThunk, IT);
			}
			else {
				PIMAGE_THUNK_DATA32 pThunk = (PIMAGE_THUNK_DATA32)(LoadAddr + imd->Characteristics - IT->VirtualAddress + IT->PointerToRawData);
				APIs = getModuleAPIs(pThunk, IT);
			}
		}

		mod.APIs = APIs;
		Modules.push_back(mod);
		
		imd++;

		if ((DWORD)imd + sizeof(*imd) >= (DWORD)LoadAddr + FileSize)
			break;

		// some files compiled with Borland compiler have imd->Characteristics = 0. But in all PEs if FirstThunk = 0, that means the end of imports
		// so why not I use imd->FirstThunk instead of imd->Characteristics?, because microsoft "optimized" some system DLLs so that fields pointed to by imd->FirstThunk
		// contains absolute addresses rather than pointers.
		if ((signed)imd->Characteristics <= 0 && imd->FirstThunk != 0)	
			imd->Characteristics = imd->FirstThunk; 

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
		// check bounds
		if (Section->PointerToRawData + Section->SizeOfRawData > FileSize)	Suspicious |= SECTION_OUTOFBOUND;

		// if it's EP section
		if ((EP >= Section->VirtualAddress) && (EP < Section->VirtualAddress+Section->Misc.VirtualSize))
		{
			if((strncmp((char *)Section->Name, ".text", IMAGE_SIZEOF_SHORT_NAME) != 0) && \
				(strncmp((char *)Section->Name, "CODE", IMAGE_SIZEOF_SHORT_NAME) != 0) )
					Suspicious |= EXEC_SECTION_IS_NOT_TEXT;
				
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
