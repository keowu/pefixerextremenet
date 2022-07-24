#include "CMemSafety.hh"

/// <summary>
///		Aloca memória de maneira segura e retorna reinterpretado com unsigned char*
/// </summary>
/// <param name="tamanho">Tamanho da alocação</param>
/// <returns>Retorna um ponteiro para o início da locação reinterpretada como UCHAR*</returns>
auto CMemSafety::getMemory( size_t tamanho ) -> unsigned char* {

	return reinterpret_cast< unsigned char* >( malloc(
		tamanho
	) );
}

/// <summary>
///		Move o conteúdo do inicio da alocação de uma memória para o inicio da locação de outra e com base no tamanho copia os bytes - 2º Deitel Polimorfismo Sobrecarga
/// </summary>
/// <param name="destino">Referência de memória alocada</param>
/// <param name="origem">Referência de memória alocada</param>
/// <param name="tamanho">Tamanho de memória alocada</param>
/// <returns>True se foi possível mover corretamente e False como negação matemática da condição alterior</returns>
auto CMemSafety::safeMemMove( void* destino, void* origem, size_t tamanho ) -> bool {

	return memcpy_s(

		destino, tamanho,
		origem, tamanho

	) == CMemSafety_ERROR::INVALID_MEMORY_ALLOCATION;
}

/// <summary>
///		Libera uma região mapeada e alocada
/// </summary>
/// <param name="mem">Referência de memória alocada</param>
auto CMemSafety::memFlush( void* mem ) -> void {
	free( 

		mem

	);
}

/// <summary>
///		Move o conteúdo do inicio da alocação de uma memória para o inicio da locação de outra e com base no tamanho copia os bytes - 2º Deitel Polimorfismo Sobrecarga
/// </summary>
/// <param name="origem">Referência de memória alocada reinterpretado como const char*</param>
/// <param name="destino">Referência de memória alocada</param>
/// <param name="tamanho">Tamanho de memória alocada</param>
/// <returns>True se foi possível mover corretamente e False como negação matemática da condição alterior</returns>
auto CMemSafety::safeMemMove( const char* origem, void* destino, size_t tamanho ) -> bool {

	return memcpy_s(

		destino, tamanho,
		origem, tamanho

	) == CMemSafety_ERROR::INVALID_MEMORY_ALLOCATION;
}