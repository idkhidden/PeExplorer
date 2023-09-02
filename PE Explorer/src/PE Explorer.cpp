#include <iostream>
#include <cstring>
#include <fstream>
#include <Windows.h>

using namespace std;

int main()
{
    SetConsoleTitle(TEXT("PE Explorer"));

    string text =
        R"(
                         ____  _____   _____            _                     
                        |  _ \| ____| | ____|_  ___ __ | | ___  _ __ ___ _ __ 
                        | |_) |  _|   |  _| \ \/ / '_ \| |/ _ \| '__/ _ \ '__|
                        |  __/| |___  | |___ >  <| |_) | | (_) | | |  __/ |   
                        |_|   |_____| |_____/_/\_\ .__/|_|\___/|_|  \___|_|  
                                                 |_| 
                                             Made By idkhidden
                                            github.com/idkhidden                         
        )";


    cout << text << endl;

    cout << "[*] Enter The PE Name: ";
    string pe;
    cin >> pe;

    ifstream file(pe.c_str(), ios::binary);
    if (!file.is_open())
    {   
        cout << "\n";
        cout << "[*] Invalid PE" << endl;

    }

    IMAGE_DOS_HEADER DosHeader;
    file.read(reinterpret_cast<char*>(&DosHeader), sizeof(IMAGE_DOS_HEADER));

    if (DosHeader.e_magic != IMAGE_DOS_SIGNATURE)
    {
        cout << "[*] Invalid DOS Sigs" << endl;

    }

    file.seekg(DosHeader.e_lfanew, std::ios::beg);

    IMAGE_NT_HEADERS NtHeader;
    file.read(reinterpret_cast<char*>(&NtHeader), sizeof(IMAGE_NT_HEADERS));

    if (NtHeader.Signature != IMAGE_NT_SIGNATURE)
    {
        cout << "[*] Invalid PE Sigs" << endl;

    }

    IMAGE_SECTION_HEADER SectionHeader;
    const int sectionHeaderSize = sizeof(IMAGE_SECTION_HEADER);
    const int numberOfSections = NtHeader.FileHeader.NumberOfSections;

    cout << "\n";
    cout << "[*] Section Headers:" << endl;
    cout << "--------------------------" << endl;


    for (int i = 0; i < numberOfSections; i++)
    {
        file.read(reinterpret_cast<char*>(&SectionHeader), sectionHeaderSize);


        char sectionName[9];
        memcpy(sectionName, SectionHeader.Name, 8);
        sectionName[8] = '\0';

        cout << "[*]" << sectionName << " | Address: 0x" << hex << SectionHeader.VirtualAddress << dec << endl;
        cout << "--------------------------" << endl;
    }
    if (!file.is_open())
    {
        cout << "[*] NULL" << endl;
    }

    system("pause");

}
