#pragma once
#include <iostream>
#include <Windows.h>
#include "CBinary.hh"
#include "CMemSafety.hh"

namespace CNetPEFixer
{

	/// <summary>
	///  Payload do bin�rio de exemplo UM para ser usado como assinatura para buscar a IAT(ImportDir)
	/// </summary>
	static unsigned char iatDirBinaryPayloadSignOne[12] {
			0x6D, 0x73, 0x63, 0x6F,
			0x72, 0x65,	0x65, 0x2E,
			0x64, 0x6C,	0x6C, 0x00
	};

	/// <summary>
	///  Payload do bin�rio de exemplo DOIS para ser usado como assinatura para buscar a IAT(ImportDir)
	/// </summary>
	static unsigned char iatDirBinaryPayloadSignTwo[12] {
			0x5F, 0x43, 0x6F, 0x72,
			0x45, 0x78, 0x65, 0x4D,
			0x61, 0x69, 0x6E, 0x00
	};

	/// <summary>
	///  Payload do bin�rio de exemplo TR�S para ser usado como assinatura para buscar a IAT(ImportDir)
	/// </summary>
	static unsigned char iatDirBinaryPayloadSignThree[12]{
			0x5F, 0x43, 0x6F, 0x72,
			0x44, 0x6C, 0x6C, 0x4D,
			0x61, 0x69, 0x6E, 0x00
	};


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
		std::byte *versionMagicString;
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

