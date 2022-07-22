#include <iostream>
#include "CBinary.hh"
#include "CNetPEFixer.hh"

using namespace CNetPEFixer; // no "STD" here my friend!

auto main() -> int
{
    std::operator<<(std::cout, "Hello World!\n");

    (void)::fixNetPE( new CBinary(
        "C:\\Users\\Joao\\Desktop\\Projetos\\Nova pasta (3)\\peparsernet\\PEFixerExtremeUI_dev.exe",
        std::ios::in | std::ios::binary
    ) );

}