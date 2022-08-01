#include "CNetPEFixer.hh"

/// <summary>
///		Esse método corrige as funções e caracterísitcas básicas para o loader da IL
/// </summary>
/// <param name="ctx">Contexto do binário</param>
auto CNetPEFixer::fixNetPE( CBinary* ctx ) -> void {
	
	bool corrigirDiretorioMetadata = true, corrigirBSJB = true, corrigirNumerosDosRVAseTamanhos = true, corrigirDiretorioNet = true, corrigirImports = true, corrigirRealocacoes = true; // EM DESENVOLVIMENTO OBVIAMENTE MUITO MAIS OPÇÕES VÃO ESTAR DISPONÍVEIS

	std::operator<<( std::operator<<( std::cout, "Corrigindo arquivo PE Net -> " ), ctx->getFilePath( ) ).operator<<( std::endl );

	ctx->mp( 0x00 );

	auto* idh = reinterpret_cast< IMAGE_DOS_HEADER * >( CMemSafety::getMemory( sizeof(IMAGE_DOS_HEADER) ) );

	ctx->r( idh, sizeof(IMAGE_DOS_HEADER) );

	if ( idh->e_magic != CBinaryType::MZ_PE_FILE )
		return;

	ctx->mp( idh->e_lfanew );

	auto* inh = reinterpret_cast< IMAGE_NT_HEADERS * >( CMemSafety::getMemory(sizeof(IMAGE_NT_HEADERS)) );

	ctx->r( inh, sizeof(IMAGE_NT_HEADERS) );

	if ( inh->Signature != CBinaryType::NT_PE_FILE )
		return;

	ctx->mp( static_cast< long >( idh->e_lfanew ) + 4 + sizeof(IMAGE_FILE_HEADER) + static_cast<int>( inh->FileHeader.SizeOfOptionalHeader ) );

	auto* sections = reinterpret_cast< IMAGE_SECTION_HEADER* >(CMemSafety::getMemory( sizeof(IMAGE_SECTION_HEADER) * inh->FileHeader.NumberOfSections) );

	ctx->r( sections, sizeof(IMAGE_SECTION_HEADER) * inh->FileHeader.NumberOfSections );

	for ( auto i = 0; i < inh->FileHeader.NumberOfSections; i++ )
		std::operator<<( std::cout, ( *(sections + i)).Name ).operator<<( std::endl );

	bool flag = true;

	/// <summary>
	///		É o MetaDataDirectory zero ? se sim deu ruim e precisa ser consertado
	/// </summary>
	/// <param name="ctx">Definir flag para falso e ir corrigir</param>
	if ( inh->OptionalHeader.DataDirectory[14].VirtualAddress < 0 )
		flag = false;
	else {
		//Por preguiça de criar um segundo parâmetro e pelo meu colega de equipe não ficar quieto eu cirei a super idolhash: superidolhash = inh->OptionalHeader.DataDirectory[14].VirtualAddress << 8 | inh->FileHeader.NumberOfSections
		int metadataDirRVA = CBinary::converterRelativeVirtualAddressToFileOffset( 
			inh->OptionalHeader.DataDirectory[14].VirtualAddress,
			inh->FileHeader.NumberOfSections,
			sections
			);
		if ( metadataDirRVA == 0 ) {
			flag = false;
		}
	}

	if ( corrigirDiretorioMetadata ) {

		if ( !flag ) {

			int newrvaMetadata = 0;
			int correctrvaMetadata = CBinary::converterRelativeVirtualAddressToFileOffset( 8192, inh->FileHeader.NumberOfSections, sections );
			if (correctrvaMetadata != 0) {

				std::operator<<( std::cout, "O RVA do diretório MetaData do PE.net é inválido, vou fazer uma busca personalizada." ).operator<<( std::endl );
			    
				//Vamos mapear todo arquivo em memória
				ctx->mp( 0x00 );
				auto* binaryBytesRaw = CMemSafety::getMemory( ctx->getFSz( ) );
				ctx->r( binaryBytesRaw, ctx->getFSz( ) ); // vamos ler todo o arquivo e armazenar uma cópia de seus bytes de maneira segura


				for ( auto i = 0; i < 30; i++ ) {
	
					bool isPatternFound = false;

					if ( *(binaryBytesRaw + (correctrvaMetadata + i)) == 72 && *(binaryBytesRaw + (correctrvaMetadata + i + 1)) == 0 && *(binaryBytesRaw + (correctrvaMetadata + i + 2)) == 0 &&
						*(binaryBytesRaw + (correctrvaMetadata + i + 3)) == 0)
						isPatternFound = true;
					
					if ( !isPatternFound )
						if (*(binaryBytesRaw + (correctrvaMetadata + i + 4)) == 2 && *(binaryBytesRaw + (correctrvaMetadata + i + 5)) == 0 && (*(binaryBytesRaw + (correctrvaMetadata + i + 6)) == 0 ||
							*(binaryBytesRaw + (correctrvaMetadata + i + 6)) == 5) && *(binaryBytesRaw + (correctrvaMetadata + i + 7)) == 0)
							isPatternFound = true;

					if ( !isPatternFound )
						if (*(binaryBytesRaw + (correctrvaMetadata + i + 16)) <= 31 && *(binaryBytesRaw + (correctrvaMetadata + i + 17)) == 0 && (*(binaryBytesRaw + (correctrvaMetadata + i + 18)) == 0 ||
							*(binaryBytesRaw + (correctrvaMetadata + i + 18)) == 1) && *(binaryBytesRaw + (correctrvaMetadata + i + 19)) <= 0 && *(binaryBytesRaw + (correctrvaMetadata + i + 23)) == 6)
							isPatternFound = true;
					
					byte b = *(binaryBytesRaw + (correctrvaMetadata + i + 16));

					if ( isPatternFound ) {
						newrvaMetadata = CBinaryType::NT_PE_NET_THEMIDA_RVA_FOR_METADATA_DIR + i;
						break;
					}
				}

				//Encerrando caso não seja possível encontrar o RVA diretório .NET Metadata
				if ( newrvaMetadata == 0 ) {
					std::operator<<( std::cout, "Falha ao tentar encontrar o RVA para o diratório Metadata .NET" )
						.operator<<( "\nVou encerrar a execução!" );
					return;
				}

				CMemSafety::safeMemMove( reinterpret_cast<void *>(newrvaMetadata), reinterpret_cast<void *>(*(binaryBytesRaw + idh->e_lfanew + 232)), sizeof(newrvaMetadata) ); //Copiando o valor do novo RVA
				int fixedRVASizeParaMetadata = 72; // Por padrão o Windows assume que o diretório Metadata em binários .NET sempre vai ter o tamanho padrão de 72
				CMemSafety::safeMemMove( reinterpret_cast<void *>( fixedRVASizeParaMetadata ), reinterpret_cast<void*>( *(binaryBytesRaw + idh->e_lfanew + 232 + 4) ), sizeof(int) ); //Vamos gravar o novo valor no arquivo atual
				
				//Limpando toda região mapeada e gravando arquivo
				ctx->mp( 0x00 );
				ctx->w( binaryBytesRaw, ctx->getFSz() ); // Vamos gravar todo conteúdo do arquivo mapeado na memória
				CMemSafety::memFlush( binaryBytesRaw ); // limpar o buffer da memória

				//Corrigindo o contexto atual que estamos trabalhando nesse arquivo
				inh->OptionalHeader.DataDirectory[14].VirtualAddress = newrvaMetadata; // Corrigindo RVA já presente na struct em memória
				inh->OptionalHeader.DataDirectory[14].Size = fixedRVASizeParaMetadata; // Definindo o tamanho do RVA padrão
				std::operator<<( std::cout, "Consegui um novo valor para seu RVA do MetaDataDirectory, agora ele será de " )
					.operator<<( std::hex ).operator<<( newrvaMetadata ).operator<<( std::endl );
				flag = true;
			}
		}

		//continuar aqui com a lógica caso o diretório metadata esteja correto e não foi destruído pelo themida ou vmprotect
		if ( !flag )//Se mesmo após todas as válidações um RVA estiver equivocado e sua flag é hora de encerrar a correção e solicitar que o usuário encontre ou determine um valor
			std::invoke( []( void ) {
				std::operator<<( std::cout, "RVA é inválido para continuar !" ).operator<<( std::endl );
				exit( -1 );
			} );
		else {

			bool isMetaDataBSJBFixed = true;
			ctx->mp( static_cast<long>( CBinary::converterRelativeVirtualAddressToFileOffset(
				inh->OptionalHeader.DataDirectory[14].VirtualAddress, inh->FileHeader.NumberOfSections, sections
			) + 8 ) );

			std::int32_t actualBSJBfield = 0;
			ctx->r( &actualBSJBfield, sizeof(std::int32_t) );//std::int32_t e int32_t é o mesmo, então não abra uma PR!

			if (actualBSJBfield <= 0)
				isMetaDataBSJBFixed = false;
			else {
				int num5 = CBinary::converterRelativeVirtualAddressToFileOffset( actualBSJBfield, inh->FileHeader.NumberOfSections, sections );
				if ( num5 == 0 )
					isMetaDataBSJBFixed = false;
				if ( isMetaDataBSJBFixed ) {
					ctx->mp( (long)num5 );
					std::int32_t num6 = 0;
					ctx->r( &num6, sizeof(std::int32_t) );
					if ( num6 != 1112167234 ) {
						isMetaDataBSJBFixed = false;
					}
				}
			}

			//Os metadados .NET apontados pelo cabeçalho CLR/CLI sempre começam com a assinatura BSJB!
			//Para quem quiser se aprofundar: https://www.codeproject.com/Articles/5841/Inside-the-NET-Application
			//								  http://www.moserware.com/2007/11/mz-bsjb-and-joys-of-magic-constants-in.html
			if ( corrigirBSJB ) {

				int valorPredizidoParaBSJB = 0;
				if ( !isMetaDataBSJBFixed ) {

					//Vamos mapear todo arquivo em memória
					ctx->mp( 0x00 );
					auto* binaryBytesRaw = CMemSafety::getMemory( ctx->getFSz( ) );
					ctx->r( binaryBytesRaw, ctx->getFSz( ) ); // vamos ler todo o arquivo e armazenar uma cópia de seus bytes de maneira segura

					for ( auto j = 0; j < ctx->getFSz( ); j++ )
					{
						if ( *(binaryBytesRaw+ j) == 66 && *(binaryBytesRaw + j + 1) == 83 && *(binaryBytesRaw + j + 2) == 74 && *(binaryBytesRaw + j + 3) == 66 )
						{
							if ( valorPredizidoParaBSJB != 0 )
							{
								valorPredizidoParaBSJB = -1;
							}
							else
							{
								valorPredizidoParaBSJB = CBinary::converterRelativeVirtualAddressToFileOffset( j, inh->FileHeader.NumberOfSections, sections );
							}
						}
					}

					std::operator<<( std::cout, "Estou corrigindo o RVA do MetaData (BSJB) !" );

					if ( valorPredizidoParaBSJB <= 0 )
						std::invoke( []( void ) {
							std::operator<<( std::cout, "Ocorreu uma falha ao tentar determinar o valor correto para o RVA do metataData(BSJB) !" );
							exit( -1 );
						} );

					std::operator<<( std::cout, "A partir de agora a ferramenta assumiu para (BSJB) o seguinte valor: " ).operator<<( std::hex ).operator<<( valorPredizidoParaBSJB );


					//Vamos salvar no arquivo o novo valor do BSJB assumido pela ferramenta
					CMemSafety::safeMemMove( &valorPredizidoParaBSJB, &*(binaryBytesRaw + ( CBinary::converterRelativeVirtualAddressToFileOffset( inh->OptionalHeader.DataDirectory[14].VirtualAddress, inh->FileHeader.NumberOfSections, sections ) + 8) ), sizeof(valorPredizidoParaBSJB) );
					
					//calculando tamanho da seção metadata!
					int sizePredicted = 0;
					std::int64_t offsetParaMetadaSecao = CBinary::converterRelativeVirtualAddressToFileOffset( valorPredizidoParaBSJB, inh->FileHeader.NumberOfSections, sections );
					ctx->mp( offsetParaMetadaSecao );
					

					/*
						AQUI É POSSÍVEL TRATAR O METADATA HEADER PARA FUTURAS APLICAÇÕES OU IDEIAS FUTURAS
						ISSO AQUI É UMA ANOTAÇÃO PARA O EU DO FUTURO, CASO DESEJA IMPLEMENTAR ALGUMA FUNÇÃO ENVOLVENDO ISSO.
					*/
					auto* mh = new MetaDataHeader;

					ctx->r( &mh->sign, sizeof(std::int32_t) );
					ctx->mp( offsetParaMetadaSecao + 4 );
					ctx->r( &mh->MajorVersion, sizeof(std::int16_t) );
					ctx->mp( offsetParaMetadaSecao + 6 );
					ctx->r( &mh->MinorVersion, sizeof(std::int16_t) );
					ctx->mp( offsetParaMetadaSecao + 8 );
					ctx->r( &mh->m$reserved, sizeof(std::int32_t) );
					ctx->mp( offsetParaMetadaSecao + 12 );
					ctx->r( &mh->length, sizeof(std::int32_t) );
					ctx->mp( offsetParaMetadaSecao + 16 );
		
					// Lógica para leitura da string da versão do cabeçalho BSJB
					std::invoke([ &mh, &ctx ] ( void ) {
						mh->versionMagicString = reinterpret_cast< std::byte* >( CMemSafety::getMemory( mh->length * sizeof(std::byte) ) ); // Byte tem o tamanho 1 de qualquer forma, porem é uma boa prática manter!
						for ( auto i = 0; i < mh->length; i++ )
							ctx->r( &*( mh->versionMagicString + i ), sizeof(byte) );
					} );

					ctx->mp( offsetParaMetadaSecao + 16 + mh->length );
					ctx->r( &mh->flags, sizeof(std::int16_t) );
					ctx->mp( offsetParaMetadaSecao + 18 + mh->length );
					ctx->r( &mh->NumberSections, sizeof(std::int16_t) );


					//Calculando o tamanho do Metadata

					auto Metasections = new MetaDataHeaderSections[ mh->NumberSections ];

					for ( auto i = 0; i < mh->NumberSections; i++ ) {

						Metasections[i].headerctx = ctx->gp( );

						ctx->r( &Metasections[i].offset, sizeof(std::int32_t) );

						ctx->r( &Metasections[i].size, sizeof(std::int32_t) );

						char tmpArr[32]{ 0 };

						int ii = 0;

						byte b = 0;

						do {

							ctx->r( &b, 1 );
							tmpArr[ ii++ ] = b;

						} while ( b != 0 );

						int quantidade = ( ii % 4 != 0 ) ? ( 4 - ii % 4 ) : 0; // Determinando a quantidade lida bytes obtida da MetaDataSection
						
						ctx->mp( ctx->gp( ) + quantidade );  // Devo mover a quantidade correta

						if ( static_cast< int >( mh->NumberSections - 1 ) == i ) 
							sizePredicted = Metasections[i].offset + Metasections[i].size; // calculando o novo tamanho para a MetaData
						

					}

					if ( sizePredicted == 0 ) 

						std::invoke( [ ] ( void ) {

							std::operator<<(
								std::cerr, "Não foi possível obter o tamanho calculado correto para a Metadata, você deve predizer um valor ou encontra manualmente, recomendo usar o IDA ou PE Bear!\n"
								);
							exit(-1);

						} );
					
					else {

						std::operator<<( std::cout, "Definido um novo tamanho para a Metadata, agora será de " )
							.operator<<( std::hex )
							.operator<<( sizePredicted )
							.operator<<( std::endl );

						//Gravando valor recalculado do tamanho de metadata
						CMemSafety::safeMemMove( &sizePredicted, &*( binaryBytesRaw + CBinary::converterRelativeVirtualAddressToFileOffset(inh->OptionalHeader.DataDirectory[14].VirtualAddress, inh->FileHeader.NumberOfSections, sections ) + 8 + 4 ), sizeof( int ) );

						ctx->mp( CBinary::converterRelativeVirtualAddressToFileOffset( inh->OptionalHeader.DataDirectory[14].VirtualAddress, inh->FileHeader.NumberOfSections, sections ) + 8 + 4 );

						ctx->w( &sizePredicted, sizeof(int) );

					}

					//Limpando toda região mapeada e gravando arquivo
					CMemSafety::memFlush( Metasections );
					ctx->mp( 0x00 );
					ctx->w( binaryBytesRaw, ctx->getFSz( ) ); // Vamos gravar todo conteúdo do arquivo mapeado na memória
					CMemSafety::memFlush( binaryBytesRaw ); // limpar o buffer da memória

					isMetaDataBSJBFixed = true;

				}

			}

			if ( !isMetaDataBSJBFixed )
				std::invoke( [ ]( void ) {
					std::operator<<( std::cout, "A ferramenta falhou ao tentar determinar o RVA para Metadata (BSJB).\n" )
									.operator<<( "Por favor descubra ou determine um novo valor !" )
									.operator<<( std::endl );
					exit( -1 );
				} );
			
			else {

				if ( corrigirNumerosDosRVAseTamanhos && inh->OptionalHeader.NumberOfRvaAndSizes != CBinaryType::NT_PE_NET_MINIMUM_RVA_SIZES ) {
					ctx->mp( static_cast< long >( idh->e_lfanew + 116 ) );
					int PE_NET_MINIMUM_RVA = 16;
					ctx->w( &PE_NET_MINIMUM_RVA, sizeof(int) );
					std::operator<<( std::cout, "O RVA tinha um problema, o tamanho dele não cumpria o requisito minimo de 16, agora eu escrevi nele 16 para que o loader deixe-o passar !" )
									.operator<<( std::endl );
				}

				//Lógica para corrigir todo o diretório .net do PE
				if ( corrigirDiretorioNet && flag && isMetaDataBSJBFixed ) {

					int rvaBase = CBinary::converterRelativeVirtualAddressToFileOffset( inh->OptionalHeader.DataDirectory[14].VirtualAddress, inh->FileHeader.NumberOfSections, sections );
					ctx->mp( rvaBase );
					std::int32_t cbField = 0; ctx->r( &cbField, sizeof(std::int32_t) );
					if ( cbField != CBinaryType::NT_PE_NET_DIR_CORRECT_CB_FIELD ) {
						std::operator<<( std::cout, "O field CB foi definido para 0x48, pois estava errado." )
							.operator<<( std::endl );
						ctx->mp( rvaBase );
						byte cbField = 72;
						ctx->w( &cbField, sizeof(byte) );
					}

					short majorRuntimeVersionRead = 0, mirorRuntimeVersionRead = 0;
					ctx->mp( rvaBase + sizeof(std::int32_t) );
					ctx->r( &majorRuntimeVersionRead, sizeof(std::int16_t) );
					ctx->r( &mirorRuntimeVersionRead, sizeof(std::int16_t) );
					
					if ( majorRuntimeVersionRead != CBinaryType::NT_PE_NET_DIR_CORRECT_MAJORRUNTIME ) {

						std::operator<<( std::cout, "O field MajorRuntimeVersion foi definido para o valor correto de 2." )
							.operator<<( std::endl );
						byte majorRuntimeVersionField = 2;
						ctx->mp( rvaBase + sizeof(std::int32_t) );
						ctx->w( &majorRuntimeVersionField, sizeof(byte) );

					}

					if ( mirorRuntimeVersionRead != CBinaryType::NT_PE_NET_DIR_CORRECT_MIRORRUNTIME && mirorRuntimeVersionRead != 0 ) {
						
						std::operator<<( std::cout, "O field MirorRuntimeVersion foi definido para o valor correto de 5" )
							.operator<<( std::endl );
						byte mirorRuntimeVersionField = 5;
						ctx->mp( rvaBase + sizeof(std::int32_t) + sizeof(std::int16_t) );
						ctx->w( &mirorRuntimeVersionField, sizeof(byte) );

					}
				}

				//Lógica para corrigir o diretório de importação completamente

			
				bool isImportDirRVAcorreto = true;
				int actualOffsetOfImportDir = 0;
				int num17 = 0;

				
				if ( inh->OptionalHeader.DataDirectory[1].VirtualAddress <= 0 )
					isImportDirRVAcorreto = { false };
				else {

					actualOffsetOfImportDir = CBinary::converterRelativeVirtualAddressToFileOffset( inh->OptionalHeader.DataDirectory[1].VirtualAddress, inh->FileHeader.NumberOfSections, sections );
					
					if ( actualOffsetOfImportDir == 0 )
						isImportDirRVAcorreto = { false };
				
					if ( CBinary::converterRelativeVirtualAddressToFileOffset( ( inh->OptionalHeader.DataDirectory[1].VirtualAddress + 40 ), inh->FileHeader.NumberOfSections, sections ) == 0 )
						isImportDirRVAcorreto = { false };

				}

				//se o rva estiver errado não faz sentido continuar nesse caso porque não tenho um lugar para começar minha busca
				// alguns protectors destroem essa informação então quando um dump é efetuado esse valor pode ser substituido pelo valor temporário utilizado, onde posso iniciar uma busca.
				// em binários nativos isso é mais dificil, por por exemplo o Vm Protect na sua versão 3.6 destroi.
				
				if ( !isImportDirRVAcorreto )
					std::invoke( [ ]( void ) {
						std::operator<<( std::cout, "Desculpe, o seu RVA para o diretório de importação está equivocado, tente conseguir corrigir ou determinar um novo RVA para que eu possa corrigir suas importações ! " ).operator<<( std::endl );
					} );
				

				int num19 = 0;
				int num18 = 0;
				int num16 = 0;
				int num13 = 0;
				
				for ( ;; ) {

					int i = 0;

					ctx->mp( 0x00 );
					auto* fileBytes = CMemSafety::getMemory( ctx->getFSz() );
					ctx->r( fileBytes, ctx->getFSz( ) );

					//1º Obter RVA, 2º calcular offset arquivo
					//https://tech-zealots.com/malware-analysis/understanding-concepts-of-va-rva-and-offset/
					int num21 = 0;

					CMemSafety::safeMemMove( &num21, &*( fileBytes + actualOffsetOfImportDir + 12 + i ), sizeof(std::int32_t) );

					int num22 = CBinary::converterRelativeVirtualAddressToFileOffset( num21, inh->FileHeader.NumberOfSections, sections );

					//Provavelmente será necessário validar o ponteiro e a área de memória
					try {

						while ( num21 != 0 && num22 != 0 ) {

							auto* buff = reinterpret_cast< unsigned char* >( CMemSafety::getMemory(12) );

							CMemSafety::safeMemMove( buff, &*(fileBytes + num22), 12 );

							//verificar e buscar padrão da IAT
							if ( CMemSafety::compareMem( CNetPEFixer::iatDirBinaryPayloadSignOne, buff, 12 ) ) {
								int num23 = 0;
								CMemSafety::safeMemMove( &num23, &*(fileBytes + actualOffsetOfImportDir + i), sizeof(std::int32_t) );

								if ( num23 > 0 ) {
									int num24 = CBinary::converterRelativeVirtualAddressToFileOffset( num23, inh->FileHeader.NumberOfSections, sections );

									if ( num24 > 0 ) {
										int num25 = 0;
										CMemSafety::safeMemMove(&num25, &*(fileBytes + num24), sizeof(std::int32_t));

										if ( num25 > 0 ) {
											int num26 = CBinary::converterRelativeVirtualAddressToFileOffset( num25, inh->FileHeader.NumberOfSections, sections );

											if ( num26 > 0 ) {
												//SEGUNDA e TERCEIRA ASSINATURA para buscar a IAT
												//RODAR CASO DE TESTE COM BINÁRIO
												auto* buff2 = reinterpret_cast<unsigned char*>( CMemSafety::getMemory( 12 ) );

												CMemSafety::safeMemMove( buff2, &*( fileBytes + num26 + 2 ), 12 );

												if ( CMemSafety::compareMem( CNetPEFixer::iatDirBinaryPayloadSignTwo, buff2, 12 )
													|| CMemSafety::compareMem( CNetPEFixer::iatDirBinaryPayloadSignThree, buff2, 12 ) ) {

													num19 = num24;
													CMemSafety::safeMemMove( &num18, &*( fileBytes + actualOffsetOfImportDir + 16 + i ), sizeof(std::int32_t) );
													CMemSafety::safeMemMove( &num16, &*( fileBytes + actualOffsetOfImportDir + i + 16 ), sizeof(std::int32_t) );

													if ( num16 != 0 ) {

														num17 = CBinary::converterRelativeVirtualAddressToFileOffset( num16, inh->FileHeader.NumberOfSections, sections );
														
														if ( num17 == 0 )
															num16 = 0;
														

													}
													if ( num17 != 0 )
														break;
													

												}

												CMemSafety::memFlush( buff2 );
											}
										}

									}
								}
							}

							CMemSafety::memFlush( buff );

							if ( num17 != 0 )
								break;

							i += 20;
							CMemSafety::safeMemMove( &num21, &*( fileBytes + actualOffsetOfImportDir + 12 + i ), sizeof( std::int32_t ) );
							num22 = CBinary::converterRelativeVirtualAddressToFileOffset( num21, inh->FileHeader.NumberOfSections, sections );
							

						}

					}
					catch ( std::exception& ex ) { std::operator<<( std::cout, "Erro de referência, Saltando stub da tabela do diretório de importação que é inválido !" ).operator<<( std::endl ); }

					if ( !corrigirImports || ( num16 != 0 && num19 != 0 && num18 != 0 ) )
						break;
					
					auto* buffWrite = new byte[ 74 ];

					std::int32_t iatrvafixFirst = inh->OptionalHeader.DataDirectory[1].VirtualAddress + 40;
					CMemSafety::safeMemMove( &*(buffWrite + 0), &iatrvafixFirst, sizeof(std::int32_t) );

					std::int32_t iatrvafixTwo = inh->OptionalHeader.DataDirectory[1].VirtualAddress + 62;
					CMemSafety::safeMemMove( &*(buffWrite + 12), &iatrvafixTwo, sizeof(std::int32_t) );

					std::int32_t iatrvafixConst = NT_PE_NET_THEMIDA_RVA_FOR_METADATA_DIR;
					CMemSafety::safeMemMove( &*(buffWrite + 12 + sizeof(int32_t)), &iatrvafixConst, sizeof(std::int32_t) );

					std::int32_t iatrvaThree = inh->OptionalHeader.DataDirectory[1].VirtualAddress + 48;
					CMemSafety::safeMemMove( &*(buffWrite + 40), &iatrvaThree, sizeof(std::int32_t) );

					CMemSafety::safeMemMove( &*(buffWrite + 50), &iatDirBinaryPayloadSignTwo, 12 );
					CMemSafety::safeMemMove( &*(buffWrite + 62), &iatDirBinaryPayloadSignOne, 12 );

					CMemSafety::safeMemMove( &*(fileBytes + actualOffsetOfImportDir), &buffWrite, 74 );

					ctx->mp( 0x00 );
					ctx->w( fileBytes, ctx->getFSz( ) );
					CMemSafety::memFlush( fileBytes );
					corrigirImports = false;
					std::operator<<( std::cout, "Toda a tabela de importação IAT foi corrigida!" ).operator<<( std::endl );
				}

				if ( num16 != 0 || ( num19 != 0 && num18 != 0 ) ) {

					ctx->mp( 0x00 );
					auto* fileBytes = CMemSafety::getMemory( ctx->getFSz( ) );
					ctx->r( fileBytes, ctx->getFSz( ) );

					if ( corrigirRealocacoes ) {

						bool flag7 = true;

						if ( inh->OptionalHeader.AddressOfEntryPoint <= 0 )
							flag7 = false;
						
						else {

							num13 = CBinary::converterRelativeVirtualAddressToFileOffset( inh->OptionalHeader.AddressOfEntryPoint, inh->FileHeader.NumberOfSections, sections );
							
							if ( num13 == 0 )
								flag7 = false;
							
							if ( CBinary::converterRelativeVirtualAddressToFileOffset( inh->OptionalHeader.AddressOfEntryPoint + 5, inh->FileHeader.NumberOfSections, sections ) == 0 )
								flag7 = false;

						}

						if ( !flag7 && num16 != 0 ) {

							int imagebaseNew = num16 + inh->OptionalHeader.ImageBase;

							auto arrayRel = new byte[ 6 ];
							arrayRel[0] = 0xFF;
							arrayRel[1] = 0x25;

							CMemSafety::safeMemMove( &*(arrayRel + 2), &imagebaseNew, sizeof(std::int32_t) );
							int num27 = 0;

							//1º

						}


						//2º



					}

					ctx->mp( 0x00 );
					ctx->w( fileBytes, ctx->getFSz( ) );
					CMemSafety::memFlush( fileBytes );

				}


				//APLICAR AQUI AS LÓGICAS PARA AS PRÓXIMAS CORREÇÕES !

			}



		}
	}

	/// <summary>
	///		Clean up memoria utilizada
	/// </summary>
	CMemSafety::memFlush( idh );
	CMemSafety::memFlush( inh );
	CMemSafety::memFlush( sections );
}