#pragma once
#include <iostream>
#include <Windows.h>
#include "CBinary.hh"
#include "CMemSafety.hh"

namespace CNetPEFixer
{

	/// <summary>
	///		MetaDataHeader - .net Microsoft Corporation
	///		Fonte: https://ntcore.com/files/dotnetformat.htm#MetaSection
	/// </summary>
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

	/// <summary>
	///		MetaDataHeaderSections - .net Microsoft Corporation
	/// </summary>
	struct MetaDataHeaderSections {
		std::int32_t headerctx;
		std::int32_t offset;
		std::int32_t size;
	};

	/// <summary>
	///		Esse método corrige as funções e caracterísitcas básicas para o loader da IL
	/// </summary>
	/// <param name="ctx">Contexto do binário</param>
	void fixNetPE(
		CBinary* ctx
	);

	/// <summary>
	///		Esse método futuramente removerá referências inválidas do binário
	/// </summary>
	/// <param name="ctx">Contexto do binário</param>
	void removeInvalidRefs(
		CBinary* ctx
	);

	/// <summary>
	///		Esse método futuramente removerá multiplas referências
	/// </summary>
	/// <param name="ctx"></param>
	void removeMultiples(
		CBinary* ctx
	);

	/// <summary>
	///		Esse método futuramente vai consertar o assembly dentro das seções
	/// </summary>
	/// <param name="ctx"></param>
	void fixNetAssembly(
		CBinary* ctx
	);

};

