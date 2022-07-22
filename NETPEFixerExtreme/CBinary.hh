#pragma once
#include <iostream>
#include <fstream>
#include <Windows.h>

enum CBinaryType {
	MZ_PE_FILE = 0x5A4D,
	NT_PE_FILE = 0x4550,
	NT_PE_NET_THEMIDA_RVA_FOR_METADATA_DIR = 0x2000
};

class CBinary
{

private:
	std::basic_fstream<char, std::char_traits<char>> f = std::basic_fstream<char>();
	std::fpos<_Mbstatet> fileSize;
	std::basic_string<char, std::char_traits<char>, std::allocator<char>> filePath;
	void calculateFileSize();

public:

	/// <summary>
	///		Construtor da classe Binary na qual vai preparar o contexto de trabalho e manipula��o do arquivo
	/// </summary>
	/// <param name="path">Path do arquivo para trabalhar</param>
	/// <param name="mode">Modo de abertura</param>
	CBinary(
		std::basic_string<char> path,
		std::ios::openmode mode
	);
	
	/// <summary>
	///		Esse m�todo � respons�vel por escrever um buffer com tamanho pr�-determinado no bin�rio
	/// </summary>
	/// <param name="buff">Buffer a ser escrito</param>
	/// <param name="buffSz">Tamanho do buffer a ser escrito</param>
	void w(
		void* buff,
		std::size_t buffSz
	);

	/// <summary>
	///		Esse m�todo � respons�vel por ler um buffer de um bin�rio com tamanho pr�-determinado
	/// </summary>
	/// <param name="buff">Buffer a ser lido do bin�rio</param>
	/// <param name="buffSz">Tamanho do buffer a ser lido do bin�rio</param>
	void r(
		void* buff,
		std::size_t buffSz
	);
	
	/// <summary>
	///		Esse m�todo � respons�vel por mover o ponteiro no bin�rio
	/// </summary>
	/// <param name="offset">offset do arquivo no qual deseja-se mover o ponteiro</param>
	void mp(
		std::int64_t offset
	);

	/// <summary>
	///		Esse m�todo � respons�vel por retornar o ponteiro atual do bin�rio seu offset
	/// </summary>
	/// <returns>offset atual do contexto do arquivo</returns>
	std::streamoff gp(
		void
	);
	
	/// <summary>
	///		Calcula o tamanho do arquivo
	/// </summary>
	std::int64_t getFSz();

	/// <summary>
	///		Obtem o path do arquivo carregado na classe cbinary
	/// </summary>
	/// <returns>Retorna um objeto std::string contendo o path</returns>
	std::basic_string<char, std::char_traits<char>, std::allocator<char>> getFilePath();

	/// <summary>
	///		Esse m�todo converte um endere�o virtual(RVA) para um offset de arquivo v�lido
	/// </summary>
	/// <param name="relativeVirtualAddress">RVA de no m�ximo 4 bytes</param>
	/// <param name="ctx">Contexto de se��o</param>
	/// <returns>O offset do arquivo</returns>
	static int converterRelativeVirtualAddressToFileOffset( std::uint64_t superidolhash, void* ctx );
	
	/// <summary>
	///		Esse m�todo fecha o contexto aberto do bin�rio no qual est� se trabalhando
	/// </summary>
	~CBinary();

};

