/* Q.701-Q.704, Q.706, Q.707 handling code */
/*
 * (C) 2010 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010 by On-Waves
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#ifndef mtp_level3_h
#define mtp_level3_h

#include <endian.h>
#include <stdint.h>
#include <sys/types.h>


/*
 * pssible service information octets..
 */
#define MTP_NI_NATION_NET	0x02

#define MTP_SI_MNT_SNM_MSG	0x00
#define MTP_SI_MNT_REG_MSG	0x01
#define MTP_SI_MNT_SCCP		0x03

/*
 * h0 contains the group, h1 the semantic of it
 */

#define MTP_TST_MSG_GRP		0x01
#define MTP_PROHIBIT_MSG_GRP	0x04
#define MTP_TRF_RESTR_MSG_GRP	0x07

/* h1 values for different groups */
#define MTP_TST_MSG_SLTM	0x01
#define MTP_TST_MSG_SLTA	0x02

#define MTP_RESTR_MSG_ALLWED	0x01

#define MTP_PROHIBIT_MSG_SIG	0x01


#define SCCP_SST	0x03
#define SCCP_SSA	0x01

#define MTP_LINK_MASK	    0x0F
#define MTP_ADDR_MASK	    0x0FFF
#define MTP_APOC_MASK 0x3f


#if __BYTE_ORDER == __LITTLE_ENDIAN
#define MTP_LINK_SLS(addr) ((addr >>28) & MTP_LINK_MASK)
#define MTP_ADDR(link, dpc, opc) \
	(((dpc)  & MTP_ADDR_MASK) << 0 |  \
	 ((opc)  & MTP_ADDR_MASK) << 14|  \
	 ((link) & MTP_LINK_MASK) << 28)
#define MTP_MAKE_APOC(apoc) \
	(apoc & 0x3fff)
#elif __BYTE_ORDER == __BIG_ENDIAN
static inline uint32_t c_swap_32(uint32_t in)
{
	return 	(((in & 0x000000ff) << 24) |
		((in & 0x0000ff00) <<  8) |
		((in & 0x00ff0000) >>  8) |
	        ((in & 0xff000000) >> 24));
}
static inline uint16_t c_swap_16(uint16_t in)
{
	return (((in & 0x00ff) << 8) |
		 (in & 0xff00) >> 8);
}
#define MTP_LINK_SLS(addr) ((c_swap_32(addr)>>28) & MTP_LINK_MASK)
#define MTP_ADDR(link, dpc, opc) \
        c_swap_32(((dpc)  & MTP_ADDR_MASK) << 0 |  \
         ((opc)  & MTP_ADDR_MASK) << 14|  \
         ((link) & MTP_LINK_MASK) << 28)
#define MTP_MAKE_APOC(apoc) \
	c_swap_16((apoc & 0x3fff))
#endif



/*
 * not the on wire address...
 */
struct mtp_addr {
	uint16_t dpc;
	uint16_t opc;
	uint8_t link;
} __attribute__((packed));

/*
 * the struct is defined in Q.704 and can be seen in the
 * wireshark dissectors too
 */
struct mtp_level_3_hdr {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t ser_ind : 4,
		 spare : 2,
		 ni : 2;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint8_t ni : 2,
		 spare : 2,
		 ser_ind : 4;
#endif
	uint32_t addr;
	uint8_t data[0];
} __attribute__((packed));

struct mtp_level_3_cmn {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t h0 : 4,
		 h1 : 4;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint8_t h1 : 4,
		 h0 : 4;
#endif
} __attribute__((packed));

struct mtp_level_3_mng {
	struct mtp_level_3_cmn  cmn;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t spare : 4,
		 length : 4;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint8_t length : 4,
		 spare : 4;
#endif
	uint8_t data[0];
} __attribute__((packed));

struct mtp_level_3_prohib {
	struct mtp_level_3_cmn  cmn;

	uint16_t apoc;
} __attribute__((packed));

struct sccp_con_ctrl_prt_mgt {
	uint8_t sst;
	uint8_t assn; /* affected sub system number */
	uint16_t apoc;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t mul_ind : 2,
		 spare : 6;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint8_t spare : 6,
		 mul_ind : 2;
#endif
} __attribute__((packed));

#endif
