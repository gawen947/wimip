/* Copyright (c) 2016, David Hauweele <david@hauweele.net>
   All rights reserved.

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions are met:

    1. Redistributions of source code must retain the above copyright notice, this
       list of conditions and the following disclaimer.
    2. Redistributions in binary form must reproduce the above copyright notice,
       this list of conditions and the following disclaimer in the documentation
       and/or other materials provided with the distribution.

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
   ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
   DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
   ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
   (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
   LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
   ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/socket.h>

#include "af-str.h"

#define AF(af) case(AF_ ## af): return "AF_" #af; break

const char * af_str(unsigned int af)
{
  switch(af) {
    /* taken from FreeBSD sys/socket.h */
    AF(UNSPEC);
    AF(UNIX);
    AF(INET);
    AF(INET6);
    AF(IMPLINK);
    AF(PUP);
    AF(CHAOS);
    AF(NETBIOS);
    AF(ISO);
    AF(ECMA);
    AF(DATAKIT);
    AF(CCITT);
    AF(SNA);
    AF(DECnet);
    AF(DLI);
    AF(LAT);
    AF(HYLINK);
    AF(APPLETALK);
    AF(ROUTE);
    AF(LINK);
    AF(COIP);
    AF(CNT);
    AF(IPX);
    AF(SIP);
    AF(ISDN);
    AF(NATM);
    AF(ATM);
    AF(NETGRAPH);
    AF(SLOW);
    AF(SCLUSTER);
    AF(ARP);
    AF(BLUETOOTH);
    AF(IEEE80211);
    AF(INET_SDP);
    AF(INET6_SDP);
  default:
    return "unknown AF";
  }
}
