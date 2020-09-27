//
//  libmachdecrypt.cpp
//  libmachdecrypt
//
//  Created by svc64 on 9/27/20.
//

#include <iostream>
#include "libmachdecrypt.hpp"
#include "libmachdecryptPriv.hpp"

void libmachdecrypt::HelloWorld(const char * s)
{
    libmachdecryptPriv *theObj = new libmachdecryptPriv;
    theObj->HelloWorldPriv(s);
    delete theObj;
};

void libmachdecryptPriv::HelloWorldPriv(const char * s) 
{
    std::cout << s << std::endl;
};

