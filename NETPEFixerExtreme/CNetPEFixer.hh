#pragma once
#include <iostream>
#include <Windows.h>
#include "CBinary.hh"
#include "CMemSafety.hh"

namespace CNetPEFixer
{

	//Fonte: https://ntcore.com/files/dotnetformat.htm#MetaSection
	struct MetaDataHeader {
		std::int32_t sign;
		std::int16_t MajorVersion;
		std::int16_t MinorVersion;
		std::int32_t m$reserved;
		std::int32_t length;
		std::int32_t versionMagicString;
		std::int16_t flags;
		std::int16_t NumberSections;
	};

	struct MetaDataHeaderSections {
		std::int32_t headerctx;
		std::int32_t offset;
		std::int32_t size;
	};

	void fixNetPE(CBinary* ctx);
	void removeInvalidRefs();
	void removeMultiples();
	void fixNetAssembly();

};

