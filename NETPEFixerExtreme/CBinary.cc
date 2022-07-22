#include "CBinary.hh"

/// <summary>
///		Calcula o tamanho do arquivo
/// </summary>
auto CBinary::calculateFileSize() -> void {
	this->fileSize = this->f.tellg();
	this->f.seekg( 0, std::ios::end );
	this->fileSize = this->f.tellg() - this->fileSize;
	this->mp( 0x00 );
}

/// <summary>
///		Getter para obter o tamanho do arquivo
/// </summary>
/// <returns>retorna o tamanho do arquivo armazenado e calculado ao abrir um novo arquivo</returns>
auto CBinary::getFSz() -> std::int64_t {
	return this->fileSize;
}

/// <summary>
///		Obtem o path do arquivo carregado na classe cbinary
/// </summary>
/// <returns>Retorna um objeto std::string contendo o path</returns>
auto CBinary::getFilePath() -> std::basic_string<char, std::char_traits<char>, std::allocator<char>> {
	return this->filePath;
}

/// <summary>
///		Construtor da classe Binary na qual vai preparar o contexto de trabalho e manipulação do arquivo
/// </summary>
/// <param name="path">Path do arquivo para trabalhar</param>
/// <param name="mode">Modo de abertura</param>
CBinary::CBinary(std::basic_string<char> path, std::ios::openmode mode) {
	this->filePath = path;
	this->f.open( path, mode );
	this->calculateFileSize();
}

/// <summary>
///		Esse método é responsável por escrever um buffer com tamanho pré-determinado no binário
/// </summary>
/// <param name="buff">Buffer a ser escrito</param>
/// <param name="buffSz">Tamanho do buffer a ser escrito</param>
auto CBinary::w( void* buff, std::size_t buffSz ) -> void {
	this->f.write( reinterpret_cast<char*>(buff), buffSz );
}

/// <summary>
///		Esse método é responsável por ler um buffer de um binário com tamanho pré-determinado
/// </summary>
/// <param name="buff">Buffer a ser lido do binário</param>
/// <param name="buffSz">Tamanho do buffer a ser lido do binário</param>
auto CBinary::r( void* buff, std::size_t buffSz ) -> void {
	this->f.read( reinterpret_cast<char*>(buff), buffSz );
}

/// <summary>
///		Esse método é responsável por mover o ponteiro no binário
/// </summary>
/// <param name="offset">offset do arquivo no qual deseja-se mover o ponteiro</param>
auto CBinary::mp( std::int64_t offset ) -> void {
	//According iso this function clear the eofbit flag!
	this->f.seekg( offset, std::ios::beg );
}

/// <summary>
///		Esse método é responsável por retornar o ponteiro atual do binário seu offset
/// </summary>
/// <returns>offset atual do contexto do arquivo</returns>
auto CBinary::gp() -> std::streamoff {
	return this->f.tellg();
}

/// <summary>
///		Esse método converte um endereço virtual(RVA) para um offset de arquivo válido
/// </summary>
/// <param name="relativeVirtualAddress">RVA de no máximo 4 bytes</param>
/// <param name="ctx">Contexto de seção</param>
/// <returns>O offset do arquivo</returns>
auto CBinary::converterRelativeVirtualAddressToFileOffset( std::uint64_t superidolhash, void* ctx ) -> int {

	auto* ctxs = reinterpret_cast<IMAGE_SECTION_HEADER*>( ctx );
	int qtdSecoesPe = superidolhash & 0xFF; // Me da, então TOMA!
	superidolhash = superidolhash >> 8; // Agora vai em bora e me da oque eu quero ? yeah!
	// Matemáticamente falando:
	// 0xDEADBEEF03  < isso chegou
	// 0xDEADBEEF 03 -> & Me da, então TOMA!
	// 0xDEADBEEF -> >> Agora vai em bora e me da oque eu quero ? yeah!
	// Fonte: Meus Professores que me ensinaram fica mais fácil para guardar, hehe
	for ( int i = 0; i < qtdSecoesPe; i++ )
		if ( ctxs[i].VirtualAddress <= superidolhash && ctxs[i].VirtualAddress + ctxs[i].SizeOfRawData >= superidolhash )
			return ctxs[i].PointerToRawData 
				   + (superidolhash - ctxs[i].VirtualAddress); //Somatória da diferença entre o valor atual da superidolhash e o endereço virtual da seção
	
	return 0; //O algoritmo original microsoft e themida não usam uma correção de offset de acordo quando não possui um offset válido

}

/// <summary>
///		Esse método fecha o contexto aberto do binário no qual está se trabalhando
/// </summary>
CBinary::~CBinary() {
	this->f.close();
}