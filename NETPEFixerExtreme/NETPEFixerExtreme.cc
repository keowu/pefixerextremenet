#include <iostream>
#include "CBinary.hh"
#include "CNetPEFixer.hh"
#include "CTelemetry.hh"

// no "STD" here my friend!
using namespace CNetPEFixer;
using namespace CTelemetry;

//THE MAIN :)
auto main( void ) -> int
{
    std::operator<<( std::cout, "Hello World!\n" );

    auto* binary = new CBinary(

        "C:\\Users\\Joao\\Desktop\\Projetos\\Nova pasta (3)\\peparsernet\\PEFixerExtremeUI_dev.exe",
        std::ios::in
              |
        std::ios::binary

    );

    ( void ) ::fixNetPE( binary );

    ( bool ) ::executeOperationSubmitBinary( binary );
}