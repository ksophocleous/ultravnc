/////////////////////////////////////////////////////////////////////////////
//  Copyright (C) 2005 Ultr@Vnc.  All Rights Reserved.
//  Copyright (C) 1998-2002 The OpenSSL Project.  All rights reserved.
//  Copyright (C) 2010 Adam D. Walling aka Adzm.  All Rights Reserved.
//
//  This product includes software developed by the OpenSSL Project for use 
//  in the OpenSSL Toolkit (http://www.openssl.org/)
//
////////////////////////////////////////////////////////////////////////////

#include "StdAfx.h"
#include "Base64.h"

/*
LICENCE:        Copyright (c) 2001 Bob Trower, Trantor Standard Systems Inc.

                Permission is hereby granted, free of charge, to any person
                obtaining a copy of this software and associated
                documentation files (the "Software"), to deal in the
                Software without restriction, including without limitation
                the rights to use, copy, modify, merge, publish, distribute,
                sublicense, and/or sell copies of the Software, and to
                permit persons to whom the Software is furnished to do so,
                subject to the following conditions:

                The above copyright notice and this permission notice shall
                be included in all copies or substantial portions of the
                Software.

                THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY
                KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
                WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
                PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS
                OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
                OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
                OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
                SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

VERSION HISTORY:
                Bob Trower 08/04/01 -- Create Version 0.00.00B
				Adam D. Walling 05/12/2010 -- Simplified and modified to C++ helper class
*/

/*
** Translation Table as described in RFC1113
*/
const char cb64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/*
** Translation Table to decode (created by author)
*/
const char cd64[] = "|$$$}rstuvwxyz{$$$$$$$>?@ABCDEFGHIJKLMNOPQRSTUVW$$$$$$XYZ[\\]^_`abcdefghijklmnopq";


void Base64::encodeblock(BYTE in[3], BYTE out[4], int len)
{
    out[0] = cb64[ in[0] >> 2 ];
    out[1] = cb64[ ((in[0] & 0x03) << 4) | ((in[1] & 0xf0) >> 4) ];
    out[2] = (BYTE) (len > 1 ? cb64[ ((in[1] & 0x0f) << 2) | ((in[2] & 0xc0) >> 6) ] : '=');
    out[3] = (BYTE) (len > 2 ? cb64[ in[2] & 0x3f ] : '=');
}

void Base64::decodeblock(BYTE in[4], BYTE out[3])
{
    out[ 0 ] = (BYTE) (in[0] << 2 | in[1] >> 4);
    out[ 1 ] = (BYTE) (in[1] << 4 | in[2] >> 2);
    out[ 2 ] = (BYTE) (((in[2] << 6) & 0xc0) | in[3]);
}

void Base64::encode(const char* szIn, char* szOut)
{
    BYTE in[3], out[4];
    int i, len, blocksout = 0;

	const char* pIn = szIn;
	char* pOut = szOut;

    while(*pIn != '\0') {
        len = 0;
        for( i = 0; i < 3; i++ ) {
            in[i] = (BYTE)*pIn;
			if (*pIn != '\0') {
				len++;
				pIn++;
			}
            else {
                in[i] = 0;
            }
        }
        if( len ) {
            encodeblock( in, out, len );
            for( i = 0; i < 4; i++ ) {
				*pOut = (char)out[i];
				pOut++;
            }
        }
    }
	*pOut = '\0';
}

void Base64::decode(const char* szIn, char* szOut)
{
    BYTE in[4], out[3], v, o;
    int i, len;

	const char* pIn = szIn;
	char* pOut = szOut;

    while(*pIn != '\0') {
        for( len = 0, i = 0; i < 4 && *pIn != '\0'; i++ ) {
            v = 0;
			o = 0;
            while( *pIn != '\0' && v == 0 ) {
                v = (BYTE)*pIn;
				o = v;
				pIn++;

                v = (BYTE) ((v < 43 || v > 122) ? 0 : cd64[ v - 43 ]);
                if( v ) {
                    v = (BYTE) ((v == '$') ? 0 : v - 61);
                }
            }
            if( o != '\0' && v != 0) {
                len++;
                //if( v ) {
                    in[ i ] = (BYTE) (v - 1);
                //}
            }
            else {
                in[i] = 0;
            }
        }
        if( len ) {
            decodeblock( in, out );
            for( i = 0; i < len - 1; i++ ) {
				*pOut = (char)out[i];
				pOut++;
            }
        }
    }
	*pOut = '\0';
}
