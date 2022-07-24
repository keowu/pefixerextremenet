#pragma once
#include "CBinary.hh"
#include <iostream>

namespace CTelemetry
{
	/// <summary>
	///		Esse m�todo prepara o payload local para enviar bin�rios para o servidor do discord para analise manual e estudos
	/// </summary>
	/// <param name="ctx">Contexto do bin�rio</param>
	/// <returns>Se a requisi��o foi aceita e o usu�rio concordou ou se ocorreu algum problema ao enviar a requisi��o</returns>
	auto executeOperationSubmitBinary(
		CBinary* ctx
	) -> bool;

};

