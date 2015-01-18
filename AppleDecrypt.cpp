/*
 * Copyright (c) 2006-2008 Dale Walsh. All rights reserved.
 *
 * @BUILDSMART_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the BUILDSMART Public Source License Version 1.0 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.daleenterprise.com.com/bpsl/bpsl.txt and read it before
 * using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND BUILDSMART HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @BUILDSMART_LICENSE_HEADER_END@
 */

#include <mach/mach_types.h>
#include <mach/machine.h>
#include <pexpert/pexpert.h>
#include <string.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOService.h>

extern "C"
{
	typedef int (*dsmos_page_transform_hook_t) (const void *, void *, unsigned long long, void*);
	void dsmos_page_transform_hook (dsmos_page_transform_hook_t hook);

#include "corecrypto/ccblowfish.h"
}

int fVerbose;

class com_AnVST_apple_decrypt : public IOService
{
OSDeclareDefaultStructors(com_AnVST_apple_decrypt)
public:
	virtual bool init(OSDictionary *dictionary = 0);
	virtual void free(void);
	/*virtual IOService *probe(IOService *provider, SInt32 *score);*/
	virtual bool start(IOService *provider);
	virtual void stop(IOService *provider);
};

#define super IOService
OSDefineMetaClassAndStructors (com_AnVST_apple_decrypt, IOService)

#if defined(__i386__) || defined(__x86_64__)
static const unsigned char plain_key[65] = "ourhardworkbythesewordsguardedpleasedontsteal(c)AppleComputerInc";
#endif

int page_transform (const void *in_blk, void *out_blk, __unused unsigned long long src_offset, __unused void *ops)
{
#if defined(__i386__) || defined(__x86_64__)
    unsigned char in_iv[32];

    if (!in_blk || !out_blk)
    {
        return KERN_FAILURE;
    }

	memset(in_iv, 0, 32);

    cccbc_one_shot(ccblowfish_cbc_decrypt_mode(),
                   64, plain_key,
                   in_iv, (PAGE_SIZE / cccbc_block_size(ccblowfish_cbc_decrypt_mode())),
                   in_blk, out_blk);

    if (fVerbose)
	{
		IOLog ("AppleDecrypt: page_transform: in_blk = 0x%lx, out_blk = 0x%lx\n", (unsigned long)in_blk, (unsigned long)out_blk);
	}
#endif

	return KERN_SUCCESS;
}

bool com_AnVST_apple_decrypt::init (OSDictionary *dict)
{
	if (fVerbose)
	{
		IOLog ("AnV Sinetek AppleDecrypt: Initializing...\n");
	}
	bool res = super::init (dict);

#if defined(__i386__) || defined(__x86_64__)
    dsmos_page_transform_hook(page_transform);

	if (fVerbose)
	{
		IOLog ("AnV Sinetek AppleDecrypt: Hook and decryption contexts set!\n");
	}
#else
	if (fVerbose)
	{
		IOLog ("AnV Sinetek AppleDecrypt: Not used for ppc...\n");
	}
#endif
	return res;
}

void com_AnVST_apple_decrypt::free ()
{
	if (fVerbose)
	{
		IOLog ("AnV Sinetek AppleDecrypt: Freeing...\n");
	}
	super::free ();
}

bool com_AnVST_apple_decrypt::start (IOService *provider)
{
	fVerbose = 0;
	PE_parse_boot_argn("decrypt", &fVerbose, sizeof(fVerbose));
	if (fVerbose)
	{
		IOLog ("AnV Sinetek AppleDecrypt: Starting...\n");
	}
	bool res = super::start (provider);
#if defined(__i386__) || defined(__x86_64__)
	registerService();
#else
	if (fVerbose)
	{
		IOLog ("AnV Sinetek AppleDecrypt: Not used for ppc...\n");
	}
#endif
	return res;
}

void com_AnVST_apple_decrypt::stop (IOService *provider)
{
	if (fVerbose)
	{
		IOLog ("AnV Sinetek AppleDecrypt: Stopping...\n");
	}
#if defined(__i386__) || defined(__x86_64__)
	super::stop (provider);
	dsmos_page_transform_hook (NULL);
	if (fVerbose)
	{
		IOLog ("AnV Sinetek AppleDecrypt: Hook and decryption contexts unset!\n");
	}
#else
	if (fVerbose)
	{
		IOLog ("AnV Sinetek AppleDecrypt: Not used for ppc...\n");
	}
#endif
}
