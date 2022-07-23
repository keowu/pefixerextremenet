#include <iostream>
#include "CBinary.hh"
#include "CNetPEFixer.hh"

// no "STD" here my friend!
using namespace CNetPEFixer;

//THE MAIN :)
auto main( void ) -> int
{
    std::operator<<( std::cout, "Hello World!\n" );

    ( void ) ::fixNetPE( new CBinary(
        "C:\\Users\\Joao\\Desktop\\Projetos\\Nova pasta (3)\\peparsernet\\PEFixerExtremeUI_dev.exe",
        std::ios::in 
        |
        std::ios::binary
    ) );

}