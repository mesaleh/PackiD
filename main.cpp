/*
 * main.cpp
 *
 *  Author: Moustafa Saleh
 *  Email: msaleh83@gmail.com
 */


//#endif

#ifdef _DEBUG
//#include "vld.h"
#endif


#include <iostream>
#include <ctime>
#include <iomanip>
#include <windows.h>
#include "PE.h"
#include "PackiD.h"
#include "Util.h"

using namespace std;

int main(int argc, char* argv[])
{

	clock_t start_s = clock();

	if( argc < 2 )
	{
	  cout << "Usage: " << argv[0] << " [file(s)]" << endl;
	  return 0;
	}

	int i;
	if(!strcmp(argv[1], "-d"))	i = 2;
	else						i = 1;

	int TotalFiles = argc - i;
	int matched = 0;

	cout << "Loading signature database." << endl;

	PackiD iD((char*)"userdb.txt");
	iD.setMode(MODE_DEEP);

	if(!iD.isDbLoaded())	{
		cout << "Cannot load the db" << endl;
		return 0;
	}

	clock_t stop_s = clock();
	cout << "Database loaded in: " << (double)(stop_s-start_s)/double(CLOCKS_PER_SEC)*1000 << "ms" << endl;
	start_s = clock();


	for(; i < argc; i++)
	{
		PE P;
		cout << "Processing file '" << getFileName(argv[i]).c_str() << "': ";

		if(!P.loadPE(argv[i])) {
			cout << "is not a PE or file cannot be opened!" << endl;
			continue;
		}

		try
		{
			string result = iD.scanPE(P);
			if(result.compare(NO_MATCH)) {
				cout << result << endl;
				matched++;
			}			
			else	cout << "mismatch!" << endl;
		}
		catch (std::exception& e)
		{
			std::cerr << "exception caught: " << e.what() << '\n';
			break;
		}


	}

	stop_s = clock();
	cout << endl << "Finished scanning in: " << (double)(stop_s-start_s)/double(CLOCKS_PER_SEC)*1000 << "ms - matched " << matched << " of " << TotalFiles << " files." << endl;

	return 0;
}

