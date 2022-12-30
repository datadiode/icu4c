// ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// PatchPE 2.0 - Copyright (c) 2017-2022 by Javier Gutierrez Chamorro et al.
// Patches PE headers to make them compatible with older versions of Windows
// or, in the occasional case of data-only DLLs, make them work on Windows CE.
//
// SPDX-License-Identifier: MIT
// ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <windows.h>

struct PEHeader
{
	DWORD Signature;
	IMAGE_FILE_HEADER FileHeader;
	union
	{
		WORD Magic;
		struct { unsigned : 8, M32 : 1; };
		struct { unsigned : 9, M64 : 1; };
		struct { unsigned : 16, MajorLinkerVersion : 8; };
		struct { unsigned : 24, MinorLinkerVersion : 8; };
		IMAGE_OPTIONAL_HEADER32 OptionalHeader32;
		IMAGE_OPTIONAL_HEADER64 OptionalHeader64;
	};

	WORD &Subsystem()					{ return M32 ? OptionalHeader32.Subsystem					: OptionalHeader64.Subsystem;					}
	WORD &DllCharacteristics()			{ return M32 ? OptionalHeader32.DllCharacteristics			: OptionalHeader64.DllCharacteristics;			}
	DWORD &SectionAlignment()			{ return M32 ? OptionalHeader32.SectionAlignment			: OptionalHeader64.SectionAlignment;			}
	DWORD &FileAlignment()				{ return M32 ? OptionalHeader32.FileAlignment				: OptionalHeader64.FileAlignment;				}
	WORD &MajorOperatingSystemVersion() { return M32 ? OptionalHeader32.MajorOperatingSystemVersion	: OptionalHeader64.MajorOperatingSystemVersion;	}
	WORD &MinorOperatingSystemVersion() { return M32 ? OptionalHeader32.MinorOperatingSystemVersion	: OptionalHeader64.MinorOperatingSystemVersion;	}
	WORD &MajorImageVersion()			{ return M32 ? OptionalHeader32.MajorImageVersion			: OptionalHeader64.MajorImageVersion;			}
	WORD &MinorImageVersion()			{ return M32 ? OptionalHeader32.MinorImageVersion			: OptionalHeader64.MinorImageVersion;			}
	WORD &MajorSubsystemVersion()		{ return M32 ? OptionalHeader32.MajorSubsystemVersion		: OptionalHeader64.MajorSubsystemVersion;		}
	WORD &MinorSubsystemVersion()		{ return M32 ? OptionalHeader32.MinorSubsystemVersion		: OptionalHeader64.MinorSubsystemVersion;		}

	size_t FollowupSize() const
	{
		switch (Magic)
		{
		case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
			return sizeof OptionalHeader32 - sizeof Magic;
		case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
			return sizeof OptionalHeader64 - sizeof Magic;
		}
		return 0;
	}
};

// ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------
extern "C" int wmain(int argc, WCHAR *argv[])
{
	IMAGE_DOS_HEADER udtDOSHeader;
	PEHeader udtPEHeader;
	size_t const preambleSize = RTL_SIZEOF_THROUGH_FIELD(PEHeader, Magic);

	wprintf(L"PatchPE 2.0 - Copyright (c) 2017-2022 by Javier Gutierrez Chamorro et al.\n"
			L"Patches PE headers to make them compatible with older versions of Windows\n"
			L"or, in the occasional case of data-only DLLs, make them work on Windows CE.\n\n");
	
	if (argc < 2)
	{
		wprintf(L"Usage: patchpe.exe <File> [<Options>]\n"
				L"\n"
				L"Example: patchpe.exe notepad.exe /Default\n"
				L"\n"
				L"Available options:\n"
				L"/Copy <File>                     Create and operate on a copy of the file\n"
				L"/Default                         Apply default modifications as of v1.35\n"
				L"/Machine <Value>                 Modify IMAGE_FILE_HEADER accordingly\n"
				L"/Characteristics <Value>         Modify IMAGE_FILE_HEADER accordingly\n"
				L"/LinkerVersion <Value>           Modify IMAGE_OPTIONAL_HEADER accordingly\n"
				L"/Subsystem <Value>               Modify IMAGE_OPTIONAL_HEADER accordingly\n"
				L"/DllCharacteristics <Value>      Modify IMAGE_OPTIONAL_HEADER accordingly\n"
				L"/OperatingSystemVersion <Value>  Modify IMAGE_OPTIONAL_HEADER accordingly\n"
				L"/ImageVersion <Value>            Modify IMAGE_OPTIONAL_HEADER accordingly\n"
				L"/SubsystemVersion <Value>        Modify IMAGE_OPTIONAL_HEADER accordingly\n"
				L"/Like <File>                     Use values from given PE file\n"
				L"\n"
				L"If no options are given, no patching takes place.\n"
				L"If the /Copy option is given, it must precede all other options.\n"
				L"If the /Like option is given, subsequent options go without values.\n");
		return(-1);
	}

	int i = 1;
	if (argc > 3 && _wcsicmp(argv[2], L"/Copy") == 0)
	{
		if (!CopyFileW(argv[1], argv[3], FALSE))
		{
			wprintf(L"Cannot copy %s to %s\n", argv[1], argv[3]);
			return(-2);
		}
		i = 3;
	}

	WCHAR *const r = argv[i];
	FILE *const pFile = _wfopen(r, argc > 2 ? L"r+b" : L"rb");
	if (!pFile)
	{
		wprintf(L"Cannot read input file %s\n", r);
		return(-3);
	}

	//Read DOS header
	if (fread(&udtDOSHeader, 1, sizeof(udtDOSHeader), pFile) != sizeof(udtDOSHeader))
	{
		wprintf(L"Cannot read DOS header %s\n", r);
		_fcloseall();
		return(-4);
	}
	if ((udtDOSHeader.e_magic != MAKEWORD('M','Z')) && (udtDOSHeader.e_magic != MAKEWORD('Z','M')))
	{
		wprintf(L"Not a valid DOS Executable %s\n", r);
		_fcloseall();
		return(-5);
	}

	//Read PE Header preamble
	if (fseek(pFile, udtDOSHeader.e_lfanew, SEEK_SET) != 0)
	{
		wprintf(L"Cannot seek to read PE header %s\n", r);
		_fcloseall();
		return(-6);
	}

	if (fread(&udtPEHeader, 1, preambleSize, pFile) != preambleSize)
	{
		wprintf(L"Cannot read PE header preamble %s\n", r);
		_fcloseall();
		return(-7);
	}
	if (udtPEHeader.Signature != MAKEWORD('P','E'))
	{
		wprintf(L"Not a valid PE Executable. Invalid PE header %s\n", r);
		_fcloseall();
		return(-8);
	}

	//Check PE Optional header and read followup bytes
	if (size_t const followupSize = udtPEHeader.FollowupSize())
	{
		if (fread(&udtPEHeader.Magic + 1, 1, followupSize, pFile) != followupSize)
		{
			wprintf(L"Cannot read PE header followup %s\n", r);
			_fcloseall();
			return(-9);
		}
	}
	else
	{
		wprintf(L"Not a valid PE Executable. Invalid optional PE header %s\n", r);
		_fcloseall();
		return(-10);
	}

	wprintf(L"File: %s\n", r);
	wprintf(L"Machine: 0x%04X\n", udtPEHeader.FileHeader.Machine);
	wprintf(L"Bitness: %d\n", (udtPEHeader.M32 << 5) | (udtPEHeader.M64 << 6));
	wprintf(L"Characteristics: 0x%04X\n", udtPEHeader.FileHeader.Characteristics);
	wprintf(L"Linker Version: %u.%u\n", udtPEHeader.MajorLinkerVersion, udtPEHeader.MinorLinkerVersion);
	wprintf(L"Subsystem: %u\n", udtPEHeader.Subsystem());
	wprintf(L"Dll Characteristics: 0x%04X\n", udtPEHeader.DllCharacteristics());
	wprintf(L"Section Alignment: 0x%08X\n", udtPEHeader.SectionAlignment());
	wprintf(L"File Alignment: 0x%08X\n", udtPEHeader.FileAlignment());
	wprintf(L"Operating System Version: %u.%u\n", udtPEHeader.MajorOperatingSystemVersion(), udtPEHeader.MinorOperatingSystemVersion());
	wprintf(L"Image Version: %u.%u\n", udtPEHeader.MajorImageVersion(), udtPEHeader.MinorImageVersion());
	wprintf(L"Subsystem Version: %u.%u\n", udtPEHeader.MajorSubsystemVersion(), udtPEHeader.MinorSubsystemVersion());
	wprintf(L"Large Address Aware: %s\n", udtPEHeader.FileHeader.Characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE ? L"Yes (>3GB)" : L"No (2GB)");
	wprintf(L"Aggressively trim the working set: %s\n", udtPEHeader.FileHeader.Characteristics & IMAGE_FILE_AGGRESIVE_WS_TRIM ? L"Yes" : L"No");

	if (fseek(pFile, udtDOSHeader.e_lfanew, SEEK_SET) != 0)
	{
		wprintf(L"Cannot seek to write new PE header %s\n", r);
		_fcloseall();
		return(-11);
	}

	//Patch header
	FILE *pLike = NULL;
	PEHeader udtPEHeaderLike = udtPEHeader;
	PEHeader udtPEHeaderUnpatched = udtPEHeader;
	while (++i < argc)
	{
		WCHAR *s = argv[i];
		WCHAR *t = NULL;
		if (_wcsicmp(s, L"/Default") == 0)
		{
			//Apply default modifications as of v1.35
			udtPEHeader.MajorOperatingSystemVersion() = 4;
			udtPEHeader.MinorOperatingSystemVersion() = 0;
			udtPEHeader.MajorSubsystemVersion() = 4;
			udtPEHeader.MinorSubsystemVersion() = 0;
			udtPEHeader.FileHeader.Characteristics |= (IMAGE_FILE_LARGE_ADDRESS_AWARE | IMAGE_FILE_AGGRESIVE_WS_TRIM);
		}
		else if (pLike || (++i < argc))
		{
			if (pLike == NULL)
				t = argv[i];
			if (t && _wcsicmp(s, L"/Like") == 0)
			{
				pLike = _wfopen(t, L"rb");
				if (!pLike)
				{
					wprintf(L"Cannot read input file %s\n", t);
					_fcloseall();
					return(-12);
				}

				//Read DOS header
				if (fread(&udtDOSHeader, 1, sizeof(udtDOSHeader), pLike) != sizeof(udtDOSHeader))
				{
					wprintf(L"Cannot read DOS header %s\n", t);
					_fcloseall();
					return(-13);
				}
				if ((udtDOSHeader.e_magic != MAKEWORD('M','Z')) && (udtDOSHeader.e_magic != MAKEWORD('Z','M')))
				{
					wprintf(L"Not a valid DOS Executable %s\n", t);
					_fcloseall();
					return(-14);
				}

				//Read PE Header
				if (fseek(pLike, udtDOSHeader.e_lfanew, SEEK_SET) != 0)
				{
					wprintf(L"Cannot seek to read PE header %s\n", t);
					_fcloseall();
					return(-15);
				}
				if (fread(&udtPEHeaderLike, 1, preambleSize, pLike) != preambleSize)
				{
					wprintf(L"Cannot read PE header preamble %s\n", t);
					_fcloseall();
					return(-16);
				}
				if (udtPEHeaderLike.Signature != MAKEWORD('P','E'))
				{
					wprintf(L"Not a valid PE Executable. Invalid PE header %s\n", t);
					_fcloseall();
					return(-17);
				}

				//Check PE Optional header and read followup bytes
				if (size_t const followupSize = udtPEHeaderLike.FollowupSize())
				{
					if (fread(&udtPEHeaderLike.Magic + 1, 1, followupSize, pLike) != followupSize)
					{
						wprintf(L"Cannot read PE header followup %s\n", r);
						_fcloseall();
						return(-18);
					}
				}
				else
				{
					wprintf(L"Not a valid PE Executable. Invalid optional PE header %s\n", r);
					_fcloseall();
					return(-19);
				}
			}
			else if (_wcsicmp(s, L"/Machine") == 0)
			{
				udtPEHeader.FileHeader.Machine = t ? static_cast<WORD>(wcstol(t, &s, 0)) : udtPEHeaderLike.FileHeader.Machine;
			}
			else if (_wcsicmp(s, L"/Characteristics") == 0)
			{
				udtPEHeader.FileHeader.Characteristics = t ? static_cast<WORD>(wcstol(t, &s, 0)) : udtPEHeaderLike.FileHeader.Characteristics;
			}
			else if (_wcsicmp(s, L"/LinkerVersion") == 0)
			{
				udtPEHeader.MajorLinkerVersion = t ? static_cast<BYTE>(wcstol(t, &s, 0)) : udtPEHeaderLike.MajorLinkerVersion;
				s += wcsspn(s, L".");
				udtPEHeader.MinorLinkerVersion = t ? static_cast<BYTE>(wcstol(s, &s, 0)) : udtPEHeaderLike.MinorLinkerVersion;
			}
			else if (_wcsicmp(s, L"/Subsystem") == 0)
			{
				udtPEHeader.Subsystem() = t ? static_cast<WORD>(wcstol(t, &s, 0)) : udtPEHeaderLike.Subsystem();
			}
			else if (_wcsicmp(s, L"/DllCharacteristics") == 0)
			{
				udtPEHeader.DllCharacteristics() = t ? static_cast<WORD>(wcstol(t, &s, 0)) : udtPEHeaderLike.DllCharacteristics();
			}
			else if (_wcsicmp(s, L"/SectionAlignment") == 0)
			{
				udtPEHeader.SectionAlignment() = t ? static_cast<DWORD>(wcstol(t, &s, 0)) : udtPEHeaderLike.SectionAlignment();
			}
			else if (_wcsicmp(s, L"/FileAlignment") == 0)
			{
				udtPEHeader.FileAlignment() = t ? static_cast<DWORD>(wcstol(t, &s, 0)) : udtPEHeaderLike.FileAlignment();
			}
			else if (_wcsicmp(s, L"/OperatingSystemVersion") == 0)
			{
				udtPEHeader.MajorOperatingSystemVersion() = t ? static_cast<WORD>(wcstol(t, &s, 0)) : udtPEHeaderLike.MajorOperatingSystemVersion();
				s += wcsspn(s, L".");
				udtPEHeader.MinorOperatingSystemVersion() = t ? static_cast<WORD>(wcstol(s, &s, 0)) : udtPEHeaderLike.MinorOperatingSystemVersion();
			}
			else if (_wcsicmp(s, L"/ImageVersion") == 0)
			{
				udtPEHeader.MajorImageVersion() = t ? static_cast<WORD>(wcstol(t, &s, 0)) : udtPEHeaderLike.MajorImageVersion();
				s += wcsspn(s, L".");
				udtPEHeader.MinorImageVersion() = t ? static_cast<WORD>(wcstol(s, &s, 0)) : udtPEHeaderLike.MinorImageVersion();
			}
			else if (_wcsicmp(s, L"/SubsystemVersion") == 0)
			{
				udtPEHeader.MajorSubsystemVersion() = t ? static_cast<WORD>(wcstol(t, &s, 0)) : udtPEHeaderLike.MajorSubsystemVersion();
				s += wcsspn(s, L".");
				udtPEHeader.MinorSubsystemVersion() = t ? static_cast<WORD>(wcstol(s, &s, 0)) : udtPEHeaderLike.MinorSubsystemVersion();
			}
			else
			{
				s = t; // indicates invalid option
			}
		}
		else
		{
			s = t; // indicates invalid option
		}
		if (s == t)
		{
			wprintf(L"Invalid option\n");
			_fcloseall();
			return(-20);
		}
	}

	//Write PE header if there were changes
	if (memcmp(&udtPEHeaderUnpatched, &udtPEHeader, sizeof udtPEHeader))
	{
		if (fwrite(&udtPEHeader, 1, preambleSize, pFile) != preambleSize)
		{
			wprintf(L"Cannot write new header preamble %s\n", r);
			_fcloseall();
			return(-21);
		}
		if (size_t const followupSize = udtPEHeader.FollowupSize())
		{
			if (fwrite(&udtPEHeader.Magic + 1, 1, followupSize, pFile) != followupSize)
			{
				wprintf(L"Cannot write new header followup %s\n", r);
				_fcloseall();
				return(-22);
			}
		}
		wprintf(L"\nPatched successfully!\n\n");
	}

	_fcloseall();	
	return(0);
}
