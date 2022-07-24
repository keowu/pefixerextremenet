#pragma once
#include <iostream>

/// <summary>
///		Flags de erros de memória
/// </summary>
enum CMemSafety_ERROR {

	INVALID_MEMORY_ALLOCATION = 0

};

namespace CMemSafety
{
	/// <summary>
	///		Aloca memória de maneira segura e retorna reinterpretado com unsigned char*
	/// </summary>
	/// <param name="tamanho">Tamanho da alocação</param>
	/// <returns>Retorna um ponteiro para o início da locação reinterpretada como UCHAR*</returns>
	unsigned char* getMemory(
		size_t tamanho
	);

	/// <summary>
	///		Move o conteúdo do inicio da alocação de uma memória para o inicio da locação de outra e com base no tamanho copia os bytes - 2º Deitel Polimorfismo Sobrecarga
	/// </summary>
	/// <param name="destino">Referência de memória alocada</param>
	/// <param name="origem">Referência de memória alocada</param>
	/// <param name="tamanho">Tamanho de memória alocada</param>
	/// <returns>True se foi possível mover corretamente e False como negação matemática da condição alterior</returns>
	bool safeMemMove(
		void* destino,
		void* origem,
		size_t tamanho
	);

	/// <summary>
	///		Move o conteúdo do inicio da alocação de uma memória para o inicio da locação de outra e com base no tamanho copia os bytes - 2º Deitel Polimorfismo Sobrecarga
	/// </summary>
	/// <param name="origem">Referência de memória alocada reinterpretado como const char*</param>
	/// <param name="destino">Referência de memória alocada</param>
	/// <param name="tamanho">Tamanho de memória alocada</param>
	/// <returns>True se foi possível mover corretamente e False como negação matemática da condição alterior</returns>
	bool safeMemMove(
		const char* origem,
		void* destino,
		size_t tamanho
	);

	/// <summary>
	///		Libera uma região mapeada e alocada
	/// </summary>
	/// <param name="mem">Referência de memória alocada</param>
	void memFlush(
		void* mem
	);

};

