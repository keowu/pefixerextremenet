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
	///		Esse m�todo corrige as fun��es e caracter�sitcas b�sicas para o loader da IL
	/// </summary>
	/// <param name="ctx">Contexto do bin�rio</param>
	void fixNetPE(
		CBinary* ctx
	);

	/// <summary>
	///		Esse m�todo futuramente remover� refer�ncias inv�lidas do bin�rio
	/// </summary>
	/// <param name="ctx">Contexto do bin�rio</param>
	void removeInvalidRefs(
		CBinary* ctx
	);

	/// <summary>
	///		Esse m�todo futuramente remover� multiplas refer�ncias
	/// </summary>
	/// <param name="ctx"></param>
	void removeMultiples(
		CBinary* ctx
	);

	/// <summary>
	///		Esse m�todo futuramente vai consertar o assembly dentro das se��es
	/// </summary>
	/// <param name="ctx"></param>
	void fixNetAssembly(
		CBinary* ctx
	);

};

