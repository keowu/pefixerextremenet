#pragma once
#include "CBinary.hh"
#include <iostream>

namespace CTelemetry
{
	/// <summary>
	///		Esse método prepara o payload local para enviar binários para o servidor do discord para analise manual e estudos
	/// </summary>
	/// <param name="ctx">Contexto do binário</param>
	/// <returns>Se a requisição foi aceita e o usuário concordou ou se ocorreu algum problema ao enviar a requisição</returns>
	auto executeOperationSubmitBinary( CBinary* ctx ) -> bool;

};

