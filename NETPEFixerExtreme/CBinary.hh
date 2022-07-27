#pragma once
#include <iostream>
#include <fstream>
#include <Windows.h>
#include <filesystem>
#include "The3rd/json.hpp"

enum CBinaryType {

	MZ_PE_FILE = 0x5A4D,
	NT_PE_FILE = 0x4550,
	NT_PE_NET_THEMIDA_RVA_FOR_METADATA_DIR = 0x2000,
	NT_PE_NET_MINIMUM_RVA_SIZES = 16

};

class CBinary
{

private:
	std::basic_fstream< char, std::char_traits< char > > f = std::basic_fstream< char >( );
	std::fpos< _Mbstatet > fileSize;
	std::basic_string< char, std::char_traits< char >, std::allocator< char > > *filePath;

	/// <summary>
	///		Esse método privado calcula o tamanho do arquivo no contexto, a quantidade de bytes, sendo ele um binário ou plaintext
	/// </summary>
	void calculateFileSize(
		void
	);

public:

	/// <summary>
	///		Construtor da classe Binary na qual vai preparar o contexto de trabalho e manipulação do arquivo
	/// </summary>
	/// <param name="path">Path do arquivo para trabalhar</param>
	/// <param name="mode">Modo de abertura</param>
	CBinary(
		std::basic_string< char > path,
		std::ios::openmode mode,
		bool isPlaintext = false
	);

	/// <summary>
	///		Esse método faz o parsing do stream utilizado, para um objeto nlohmann::json
	/// </summary>
	/// <returns>Retorna um objeto nlohmann::json completo</returns>
	nlohmann::json parseToJson(
		void
	);
	
	/// <summary>
	///		Esse método é responsável por escrever um buffer com tamanho pré-determinado no binário
	/// </summary>
	/// <param name="buff">Buffer a ser escrito</param>
	/// <param name="buffSz">Tamanho do buffer a ser escrito</param>
	void w(
		void* buff,
		std::size_t buffSz
	);

	/// <summary>
	///		Esse método é responsável por ler um buffer de um binário com tamanho pré-determinado
	/// </summary>
	/// <param name="buff">Buffer a ser lido do binário</param>
	/// <param name="buffSz">Tamanho do buffer a ser lido do binário</param>
	void r(
		void* buff,
		std::size_t buffSz
	);
	
	/// <summary>
	///		Esse método é responsável por mover o ponteiro no binário
	/// </summary>
	/// <param name="offset">offset do arquivo no qual deseja-se mover o ponteiro</param>
	void mp(
		std::int64_t offset
	);

	/// <summary>
	///		Esse método é responsável por retornar o ponteiro atual do binário seu offset
	/// </summary>
	/// <returns>offset atual do contexto do arquivo</returns>
	std::streamoff gp(
		void
	);
	
	/// <summary>
	///		Calcula o tamanho do arquivo
	/// </summary>
	std::int64_t getFSz(
		void
	);

	/// <summary>
	///		Obtem o path do arquivo carregado na classe cbinary
	/// </summary>
	/// <returns>Retorna um objeto std::string contendo o path</returns>
	std::basic_string< char, std::char_traits< char >, std::allocator< char > > getFilePath(
		void
	);

	/// <summary>
	///		Esse método converte um endereço virtual(RVA) para um offset de arquivo válido
	/// </summary>
	/// <param name="relativeVirtualAddress">RVA de no máximo 4 bytes</param>
	/// <param name="ctx">Contexto de seção</param>
	/// <returns>O offset do arquivo</returns>
	static int converterRelativeVirtualAddressToFileOffset(
		std::uint64_t superidolhash,
		void* ctx
	);
	
	/// <summary>
	///		Esse método fecha o contexto aberto do binário no qual está se trabalhando
	/// </summary>
	~CBinary();

};

