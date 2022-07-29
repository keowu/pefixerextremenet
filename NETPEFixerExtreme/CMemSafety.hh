#pragma once
#include <iostream>

/// <summary>
///		Flags de erros de mem�ria
/// </summary>
enum CMemSafety_ERROR {

	INVALID_MEMORY_ALLOCATION = 0,
	MEMORY_CONTENT_ARE_EQUALS = 0

};

namespace CMemSafety
{
	/// <summary>
	///		Aloca mem�ria de maneira segura e retorna reinterpretado com unsigned char*
	/// </summary>
	/// <param name="tamanho">Tamanho da aloca��o</param>
	/// <returns>Retorna um ponteiro para o in�cio da loca��o reinterpretada como UCHAR*</returns>
	unsigned char* getMemory(
		std::size_t tamanho
	);

	/// <summary>
	///		Move o conte�do do inicio da aloca��o de uma mem�ria para o inicio da loca��o de outra e com base no tamanho copia os bytes - 2� Deitel Polimorfismo Sobrecarga
	/// </summary>
	/// <param name="destino">Refer�ncia de mem�ria alocada</param>
	/// <param name="origem">Refer�ncia de mem�ria alocada</param>
	/// <param name="tamanho">Tamanho de mem�ria alocada</param>
	/// <returns>True se foi poss�vel mover corretamente e False como nega��o matem�tica da condi��o alterior</returns>
	bool safeMemMove(
		void* destino,
		void* origem,
		std::size_t tamanho
	);

	/// <summary>
	///		Move o conte�do do inicio da aloca��o de uma mem�ria para o inicio da loca��o de outra e com base no tamanho copia os bytes - 2� Deitel Polimorfismo Sobrecarga
	/// </summary>
	/// <param name="origem">Refer�ncia de mem�ria alocada reinterpretado como const char*</param>
	/// <param name="destino">Refer�ncia de mem�ria alocada</param>
	/// <param name="tamanho">Tamanho de mem�ria alocada</param>
	/// <returns>True se foi poss�vel mover corretamente e False como nega��o matem�tica da condi��o alterior</returns>
	bool safeMemMove(
		const char* origem,
		void* destino,
		std::size_t tamanho
	);

	/// <summary>
	///		Esse m�todo compara o conte�do de duas regi�es da mem�ria e verifica se s�o identicos com base em um tamanho determinado
	/// </summary>
	/// <param name="patternOne">Ponteiro para primeira regi�o a comparar</param>
	/// <param name="patternTwo">Ponteiro para segunda regi�o a comparar</param>
	/// <param name="patternSize">Tamanho da regi�o na qual deseja-se comparar</param>
	/// <returns></returns>
	bool compareMem(
		void* patternOne,
		void* patternTwo,
		std::size_t patternSize
	);

	/// <summary>
	///		Libera uma regi�o mapeada e alocada
	/// </summary>
	/// <param name="mem">Refer�ncia de mem�ria alocada</param>
	void memFlush(
		void* mem
	);

};

