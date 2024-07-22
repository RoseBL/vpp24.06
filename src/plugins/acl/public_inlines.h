/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef included_acl_inlines_h
#define included_acl_inlines_h

#include <stdint.h>

#include <vlib/unix/plugin.h>
#include <plugins/acl/acl.h>
#include <plugins/acl/fa_node.h>
#include <plugins/acl/hash_lookup_private.h>

#include <plugins/acl/exported_types.h>

#define LOAD_SYMBOL_FROM_PLUGIN_TO(p, s, st)                              \
({                                                                        \
    st = vlib_get_plugin_symbol(p, #s);                                    \
    if (!st)                                                               \
        return clib_error_return(0,                                       \
                "Plugin %s and/or symbol %s not found.", p, #s);          \
})

#define LOAD_SYMBOL(s) LOAD_SYMBOL_FROM_PLUGIN_TO("acl_plugin.so", s, s)


static inline clib_error_t * acl_plugin_exports_init (acl_plugin_methods_t *m)
{
    acl_plugin_methods_vtable_init_fn_t mvi;

    LOAD_SYMBOL_FROM_PLUGIN_TO("acl_plugin.so", acl_plugin_methods_vtable_init, mvi);
    return (mvi(m));
}

always_inline void *
get_ptr_to_offset (vlib_buffer_t * b0, int offset)
{
  u8 *p = vlib_buffer_get_current (b0) + offset;
  return p;
}

always_inline int
offset_within_packet (vlib_buffer_t * b0, int offset)
{
  /* For the purposes of this code, "within" means we have at least 8 bytes after it */
  return (offset <= (b0->current_length - 8));
}

always_inline int
offset_beyond_packet (vlib_buffer_t * b0, int offset)
{
  /* For the purposes of this code, "within" means we have at least 8 bytes after it */
  return (offset > (b0->current_length - 8));
}


/**
 * @brief Fill FA 5-tuple L3 data from a packet
 *
 * 此函数用于填充FA五元组中的L3数据，包括源和目的IP地址，基于数据包的内容。
 *
 * @param am 指向ACL主控结构的指针
 * @param b0 指向VPP缓冲区结构的指针
 * @param is_ip6 是否为IPv6数据包的标志
 * @param l3_offset L3头部相对于数据包起始位置的偏移量
 * @param p5tuple_pkt 指向FA五元组结构的指针，将被填充
 */
always_inline void
acl_fill_5tuple_l3_data (acl_main_t * am, vlib_buffer_t * b0, int is_ip6,
		 int l3_offset, fa_5tuple_t * p5tuple_pkt)
{
  if (is_ip6)
    {
      // 获取IPv6头部指针
      ip6_header_t *ip6 = vlib_buffer_get_current (b0) + l3_offset;
      // 填充IPv6源地址和目的地址
      p5tuple_pkt->ip6_addr[0] = ip6->src_address;
      p5tuple_pkt->ip6_addr[1] = ip6->dst_address;
    }
  else
    {
      int ii;
      // 清零L3零填充区域
      for(ii=0; ii<6; ii++) {
        p5tuple_pkt->l3_zero_pad[ii] = 0;
      }
      // 获取IPv4头部指针
      ip4_header_t *ip4 = vlib_buffer_get_current (b0) + l3_offset;
      p5tuple_pkt->ip4_addr[0] = ip4->src_address;
      p5tuple_pkt->ip4_addr[1] = ip4->dst_address;
    }
}

/**
 * @brief Fill FA 5-tuple L4 and packet data from a packet
 *
 * 此函数用于填充FA五元组中的L4数据和包特定数据，包括源和目的端口、协议类型、TCP标志、是否为非首片分片等信息。
 *
 * @param am 指向ACL主控结构的指针
 * @param sw_if_index0 软件接口索引
 * @param b0 指向VPP缓冲区结构的指针
 * @param is_ip6 是否为IPv6数据包的标志
 * @param is_input 是否为入站数据包的标志
 * @param l3_offset L3头部相对于数据包起始位置的偏移量
 * @param p5tuple_l4 指向FA五元组L4数据结构的指针，将被填充
 * @param p5tuple_pkt 指向FA包信息结构的指针，将被填充
 */
always_inline void
acl_fill_5tuple_l4_and_pkt_data (acl_main_t * am, u32 sw_if_index0, vlib_buffer_t * b0, int is_ip6, int is_input,
		 int l3_offset, fa_session_l4_key_t *p5tuple_l4, fa_packet_info_t *p5tuple_pkt)
{
  /* IP4 and IP6 protocol numbers of ICMP */
  // IP4和IP6的ICMP协议号数组
  static u8 icmp_protos_v4v6[] = { IP_PROTOCOL_ICMP, IP_PROTOCOL_ICMP6 };

  // L4层偏移量
  int l4_offset;
  // 源端口和目的端口数组
  u16 ports[2] = { 0 };
  // 协议类型
  u8 proto;

  // 临时L4标志
  u8 tmp_l4_flags = 0;
  // 初始化临时包信息
  fa_packet_info_t tmp_pkt = { .is_ip6 = is_ip6, .mask_type_index_lsb = ~0 };

  // 处理IPv6包
  if (is_ip6)
    {
      ip6_header_t *ip6 = vlib_buffer_get_current (b0) + l3_offset;
      proto = ip6->protocol;

      l4_offset = l3_offset + sizeof (ip6_header_t);

      /* IP6 EH handling is here, increment l4_offset if needs to, update the proto */
      // 处理IPv6扩展头部，如果需要，增加l4_offset并更新proto
      int need_skip_eh = clib_bitmap_get (am->fa_ipv6_known_eh_bitmap, proto);
      if (PREDICT_FALSE (need_skip_eh))
	{
	  while (need_skip_eh && offset_within_packet (b0, l4_offset))
	    {
	      /* Fragment header needs special handling */
        // 处理片段头部
	      if (PREDICT_FALSE(ACL_EH_FRAGMENT == proto))
	        {
	          proto = *(u8 *) get_ptr_to_offset (b0, l4_offset);
		  u16 frag_offset = *(u16 *) get_ptr_to_offset (b0, 2 + l4_offset);
		  frag_offset = clib_net_to_host_u16(frag_offset) >> 3;
		  if (frag_offset)// 非初始片段
		    {
                      tmp_pkt.is_nonfirst_fragment = 1;
                      /* invalidate L4 offset so we don't try to find L4 info */
                      // 使L4偏移量无效
                      l4_offset += b0->current_length;
		    }
		  else// 初始片段
		    {
		      /* First fragment: skip the frag header and move on. */
          // 跳过片段头部
		      l4_offset += 8;
		    }
		}
              else
                {
	          u8 nwords = *(u8 *) get_ptr_to_offset (b0, 1 + l4_offset);
	          proto = *(u8 *) get_ptr_to_offset (b0, l4_offset);
	          l4_offset += 8 * (1 + (u16) nwords);
                }
	      need_skip_eh =
		clib_bitmap_get (am->fa_ipv6_known_eh_bitmap, proto);
	    }
	}
    }
  // 处理IPv4包
  else
    {
      ip4_header_t *ip4 = vlib_buffer_get_current (b0) + l3_offset;
      proto = ip4->protocol;
      l4_offset = l3_offset + ip4_header_bytes(ip4);

      /* non-initial fragments have non-zero offset */
      // 非初始片段有非零偏移量
      if (PREDICT_FALSE(ip4_get_fragment_offset(ip4)))
        {
          tmp_pkt.is_nonfirst_fragment = 1;
          /* invalidate L4 offset so we don't try to find L4 info */
          // 使L4偏移量无效
          l4_offset += b0->current_length;
        }

    }
  tmp_l4_flags |= is_input ? FA_SK_L4_FLAG_IS_INPUT : 0;

  // 检查L4偏移量是否在包范围内
  if (PREDICT_TRUE (offset_within_packet (b0, l4_offset)))
    {
      tcp_header_t *tcph = vlib_buffer_get_current (b0) + l4_offset;
      udp_header_t *udph = vlib_buffer_get_current (b0) + l4_offset;
      tmp_pkt.l4_valid = 1;

      if (PREDICT_FALSE(icmp_protos_v4v6[is_ip6] == proto))
	{
          icmp46_header_t *icmph = vlib_buffer_get_current (b0) + l4_offset;
	  ports[0] = icmph->type;
	  ports[1] = icmph->code;
          /* ICMP needs special handling */
          // ICMP需要特殊处理
          tmp_l4_flags |= FA_SK_L4_FLAG_IS_SLOWPATH;
	}
      else if (IP_PROTOCOL_TCP == proto)
	{
          ports[0] = clib_net_to_host_u16(tcph->src_port);
          ports[1] = clib_net_to_host_u16(tcph->dst_port);
	  tmp_pkt.tcp_flags = tcph->flags;
	  tmp_pkt.tcp_flags_valid = 1;
	}
      else if (IP_PROTOCOL_UDP == proto)
	{
          ports[0] = clib_net_to_host_u16(udph->src_port);
          ports[1] = clib_net_to_host_u16(udph->dst_port);
        }
      else
        {
          // 其他协议需要慢路径处理
          tmp_l4_flags |= FA_SK_L4_FLAG_IS_SLOWPATH;
        }
    }

  // 填充包信息
  p5tuple_pkt->as_u64 = tmp_pkt.as_u64;

  // 填充五元组信息
  fa_session_l4_key_t tmp_l4 = { .port = { ports[0], ports[1] },
                                 .proto = proto,
                                 .l4_flags = tmp_l4_flags,
                                 .lsb_of_sw_if_index = sw_if_index0 & 0xffff };

  p5tuple_l4->as_u64 = tmp_l4.as_u64;
}

/**
 * @brief Fill FA 5-tuple information from a packet
 *
 * 此函数用于填充FA五元组信息，该信息是从数据包中提取的，用于ACL Fast-Action节点的决策过程。
 *
 * @param am 指向ACL主控结构的指针
 * @param sw_if_index0 软件接口索引
 * @param b0 指向VPP缓冲区结构的指针
 * @param is_ip6 是否为IPv6数据包的标志
 * @param is_input 是否为入站数据包的标志
 * @param is_l2_path 是否为二层路径的标志
 * @param p5tuple_pkt 指向FA五元组结构的指针，将被填充
 */
always_inline void
acl_fill_5tuple (acl_main_t * am, u32 sw_if_index0, vlib_buffer_t * b0, int is_ip6,
		 int is_input, int is_l2_path, fa_5tuple_t * p5tuple_pkt)
{
  int l3_offset;

  // 计算L3（网络层）头部偏移量
  if (is_l2_path)
    {
      // 对于二层路径，L3头部位于以太网头部之后
      l3_offset = ethernet_buffer_header_size(b0);
    }
  else
    {
      if (is_input)
        // 入站数据包的L3头部直接从开始位置计算
        l3_offset = 0;
      else
        // 出站数据包的L3头部偏移量可能因重写而变化
        l3_offset = vnet_buffer(b0)->ip.save_rewrite_length;
    }

  /* key[0..3] contains src/dst address and is cleared/set below */
  /* Remainder of the key and per-packet non-key data */
  // 填充五元组中的L3数据部分
  acl_fill_5tuple_l3_data(am, b0, is_ip6, l3_offset, p5tuple_pkt);
  // 填充五元组中的L4数据和包特定数据部分
  acl_fill_5tuple_l4_and_pkt_data(am, sw_if_index0, b0, is_ip6, is_input, l3_offset, &p5tuple_pkt->l4, &p5tuple_pkt->pkt);
}

always_inline void
acl_plugin_fill_5tuple_inline (void *p_acl_main, u32 lc_index, vlib_buffer_t * b0, int is_ip6,
		 int is_input, int is_l2_path, fa_5tuple_opaque_t * p5tuple_pkt)
{
  acl_main_t *am = p_acl_main;
  acl_fill_5tuple(am, 0, b0, is_ip6, is_input, is_l2_path, (fa_5tuple_t *)p5tuple_pkt);
}



/**
 * @brief Check if two IPv4 addresses match given a prefix length
 *
 * 此内联函数用于基于给定的前缀长度，判断两个IPv4地址是否匹配。它首先检查前缀长度是否为零，如果是则认为总是匹配。
 * 然后，它将两个IPv4地址转换为主机字节序，计算一个掩码，用于屏蔽掉多余的位，最后比较这两个地址是否在掩码下相等。
 *
 * @param addr1 指向第一个IPv4地址的指针
 * @param addr2 指向第二个IPv4地址的指针
 * @param prefixlen 前缀长度
 * @return 返回匹配结果，1表示匹配，0表示不匹配
 */
always_inline int
fa_acl_match_ip4_addr (ip4_address_t * addr1, ip4_address_t * addr2,
		   int prefixlen)
{
  if (prefixlen == 0)
    {
      /* match any always succeeds */
      return 1;
    }
      uint32_t a1 = clib_net_to_host_u32 (addr1->as_u32);
      uint32_t a2 = clib_net_to_host_u32 (addr2->as_u32);
      uint32_t mask0 = 0xffffffff - ((1 << (32 - prefixlen)) - 1);
      return (a1 & mask0) == a2;
}

/**
 * @brief Check if two IPv6 addresses match given a prefix length
 *
 * 此内联函数用于基于给定的前缀长度，判断两个IPv6地址是否匹配。它首先检查前缀长度是否为零，如果是则认为总是匹配。然后，它比较两个地址的前缀部分是否相同，如果不同则返回不匹配。最后，如果前缀长度不能整除8，它会进行额外的位运算来确保最后一个字节的部分匹配。
 *
 * @param addr1 指向第一个IPv6地址的指针
 * @param addr2 指向第二个IPv6地址的指针
 * @param prefixlen 前缀长度
 * @return 返回匹配结果，1表示匹配，0表示不匹配
 */
always_inline int
fa_acl_match_ip6_addr (ip6_address_t * addr1, ip6_address_t * addr2,
		   int prefixlen)
{
  if (prefixlen == 0)
    {
      /* match any always succeeds */
      return 1;
    }
      if (memcmp (addr1, addr2, prefixlen / 8))
	{
	  /* If the starting full bytes do not match, no point in bittwidling the thumbs further */
	  return 0;
	}
      if (prefixlen % 8)
	{
	  u8 b1 = *((u8 *) addr1 + 1 + prefixlen / 8);
	  u8 b2 = *((u8 *) addr2 + 1 + prefixlen / 8);
	  u8 mask0 = (0xff - ((1 << (8 - (prefixlen % 8))) - 1));
	  return (b1 & mask0) == b2;
	}
      else
	{
	  /* The prefix fits into integer number of bytes, so nothing left to do */
	  return 1;
	}
}

/**
 * @brief Check if a port number is within a specified range
 *
 * 此内联函数用于判断一个端口号是否位于给定的端口范围之内。它简单地比较端口号是否大于等于起始端口号并且小于等于结束端口号。
 *
 * @param port 待匹配的端口号
 * @param port_first 起始端口号
 * @param port_last 结束端口号
 * @param is_ip6 是否为IPv6数据包的标志（此参数在此函数中未使用）
 * @return 返回匹配结果，1表示匹配，0表示不匹配
 */
always_inline int
fa_acl_match_port (u16 port, u16 port_first, u16 port_last, int is_ip6)
{
  return ((port >= port_first) && (port <= port_last));
}

/**
 * @brief Try to match a single ACL with a 5-tuple
 *
 * 此内联函数用于基于五元组信息和单个ACL，判断数据包是否匹配ACL中的任何规则。它首先检查ACL是否存在，然后遍历ACL中的所有规则，逐个进行匹配检查。
 *
 * @param am 指向ACL主控结构的指针
 * @param acl_index ACL的索引
 * @param pkt_5tuple 指向FA五元组结构的指针
 * @param is_ip6 是否为IPv6数据包的标志
 * @param r_action 指向u8类型的指针，用于存储匹配结果的动作
 * @param r_acl_match_p 指向u32类型的指针，用于存储匹配结果的ACL索引
 * @param r_rule_match_p 指向u32类型的指针，用于存储匹配结果的规则索引
 * @param trace_bitmap 指向u32类型的指针，用于存储跟踪位图
 * @return 返回匹配结果，1表示匹配，0表示未匹配
 */
always_inline int
single_acl_match_5tuple (acl_main_t * am, u32 acl_index, fa_5tuple_t * pkt_5tuple,
		  int is_ip6, u8 * r_action, u32 * r_acl_match_p,
		  u32 * r_rule_match_p, u32 * trace_bitmap)
{
  int i;
  acl_rule_t *r;
  acl_rule_t *acl_rules;

  if (pool_is_free_index (am->acls, acl_index))
    {
      if (r_acl_match_p)
	*r_acl_match_p = acl_index;
      if (r_rule_match_p)
	*r_rule_match_p = -1;
      /* the ACL does not exist but is used for policy. Block traffic. */
      return 0;
    }
  acl_rules = am->acls[acl_index].rules;
  for (i = 0; i < vec_len(acl_rules); i++)
    {
      r = &acl_rules[i];
      if (is_ip6 != r->is_ipv6)
	{
	  continue;
	}
      if (is_ip6) {
        if (!fa_acl_match_ip6_addr
	  (&pkt_5tuple->ip6_addr[1], &r->dst.ip6, r->dst_prefixlen))
	continue;
        if (!fa_acl_match_ip6_addr
	  (&pkt_5tuple->ip6_addr[0], &r->src.ip6, r->src_prefixlen))
	continue;
      } else {
        if (!fa_acl_match_ip4_addr
	  (&pkt_5tuple->ip4_addr[1], &r->dst.ip4, r->dst_prefixlen))
	continue;
        if (!fa_acl_match_ip4_addr
	  (&pkt_5tuple->ip4_addr[0], &r->src.ip4, r->src_prefixlen))
	continue;
      }

      if (r->proto)
	{
	  if (pkt_5tuple->l4.proto != r->proto)
	    continue;

          if (PREDICT_FALSE (pkt_5tuple->pkt.is_nonfirst_fragment &&
                     am->l4_match_nonfirst_fragment))
          {
            /* non-initial fragment with frag match configured - match this rule */
            *trace_bitmap |= 0x80000000;
            *r_action = r->is_permit;
            if (r_acl_match_p)
	      *r_acl_match_p = acl_index;
            if (r_rule_match_p)
	      *r_rule_match_p = i;
            return 1;
          }

	  /* A sanity check just to ensure we are about to match the ports extracted from the packet */
	  if (PREDICT_FALSE (!pkt_5tuple->pkt.l4_valid))
	    continue;

#ifdef FA_NODE_VERBOSE_DEBUG
	  clib_warning
	    ("ACL_FA_NODE_DBG acl %d rule %d pkt proto %d match rule %d",
	     acl_index, i, pkt_5tuple->l4.proto, r->proto);
#endif

	  if (!fa_acl_match_port
	      (pkt_5tuple->l4.port[0], r->src_port_or_type_first,
	       r->src_port_or_type_last, is_ip6))
	    continue;

#ifdef FA_NODE_VERBOSE_DEBUG
	  clib_warning
	    ("ACL_FA_NODE_DBG acl %d rule %d pkt sport %d match rule [%d..%d]",
	     acl_index, i, pkt_5tuple->l4.port[0], r->src_port_or_type_first,
	     r->src_port_or_type_last);
#endif

	  if (!fa_acl_match_port
	      (pkt_5tuple->l4.port[1], r->dst_port_or_code_first,
	       r->dst_port_or_code_last, is_ip6))
	    continue;

#ifdef FA_NODE_VERBOSE_DEBUG
	  clib_warning
	    ("ACL_FA_NODE_DBG acl %d rule %d pkt dport %d match rule [%d..%d]",
	     acl_index, i, pkt_5tuple->l4.port[1], r->dst_port_or_code_first,
	     r->dst_port_or_code_last);
#endif
	  if (pkt_5tuple->pkt.tcp_flags_valid
	      && ((pkt_5tuple->pkt.tcp_flags & r->tcp_flags_mask) !=
		  r->tcp_flags_value))
	    continue;
	}
      /* everything matches! */
#ifdef FA_NODE_VERBOSE_DEBUG
      clib_warning ("ACL_FA_NODE_DBG acl %d rule %d FULL-MATCH, action %d",
		    acl_index, i, r->is_permit);
#endif
      *r_action = r->is_permit;
      if (r_acl_match_p)
	*r_acl_match_p = acl_index;
      if (r_rule_match_p)
	*r_rule_match_p = i;
      return 1;
    }
  return 0;
}

always_inline int
acl_plugin_single_acl_match_5tuple (void *p_acl_main, u32 acl_index, fa_5tuple_t * pkt_5tuple,
		  int is_ip6, u8 * r_action, u32 * r_acl_match_p,
		  u32 * r_rule_match_p, u32 * trace_bitmap)
{
  acl_main_t * am = p_acl_main;
  return single_acl_match_5tuple(am, acl_index, pkt_5tuple, is_ip6, r_action,
                                 r_acl_match_p, r_rule_match_p, trace_bitmap);
}

/**
 * @brief Perform linear match of 5-tuple against multiple ACLs
 *
 * 此内联函数用于基于五元组信息线性匹配多个ACL，遍历ACL列表并尝试与每个ACL进行匹配。
 *
 * @param p_acl_main 指向ACL主控结构的指针
 * @param lc_index 逻辑链索引
 * @param pkt_5tuple 指向FA五元组结构的指针
 * @param is_ip6 是否为IPv6数据包的标志
 * @param r_action 指向u8类型的指针，用于存储匹配结果的动作
 * @param acl_pos_p 指向u32类型的指针，用于存储匹配结果的ACL位置
 * @param acl_match_p 指向u32类型的指针，用于存储匹配结果的ACL匹配索引
 * @param rule_match_p 指向u32类型的指针，用于存储匹配结果的规则匹配索引
 * @param trace_bitmap 指向u32类型的指针，用于存储跟踪位图
 * @return 返回匹配结果，1表示匹配成功，0表示未匹配或没有ACL
 */
always_inline int
linear_multi_acl_match_5tuple (void *p_acl_main, u32 lc_index, fa_5tuple_t * pkt_5tuple,
		       int is_ip6, u8 *r_action, u32 *acl_pos_p, u32 * acl_match_p,
		       u32 * rule_match_p, u32 * trace_bitmap)
{
  acl_main_t *am = p_acl_main;
  int i;
  u32 *acl_vector;
  u8 action = 0;
  acl_lookup_context_t *acontext = pool_elt_at_index(am->acl_lookup_contexts, lc_index);

  acl_vector = acontext->acl_indices;

  for (i = 0; i < vec_len (acl_vector); i++)
    {
#ifdef FA_NODE_VERBOSE_DEBUG
      clib_warning ("ACL_FA_NODE_DBG: Trying to match ACL: %d",
		    acl_vector[i]);
#endif
      if (single_acl_match_5tuple
	  (am, acl_vector[i], pkt_5tuple, is_ip6, &action,
	   acl_match_p, rule_match_p, trace_bitmap))
	{
	  *r_action = action;
          *acl_pos_p = i;
	  return 1;
	}
    }
  if (vec_len (acl_vector) > 0)
    {
      return 0;
    }
#ifdef FA_NODE_VERBOSE_DEBUG
  clib_warning ("ACL_FA_NODE_DBG: No ACL on lc_index %d", lc_index);
#endif
  /* If there are no ACLs defined we should not be here. */
  return 0;
}



/*
 * This returns true if there is indeed a match on the portranges.
 * With all these levels of indirections, this is not going to be very fast,
 * so, best use the individual ports or wildcard ports for performance.
 */
/**
 * @brief 端口范围匹配
 *
 * 此函数用于检查数据包的源端口和目的端口是否落在ACL（Access Control List）规则所定义的端口范围内。
 *
 * @param am 指向ACL主控结构的指针
 * @param match 指向包含数据包五元组信息的结构体指针
 * @param index ACL规则索引
 *
 * @return 如果源端口和目的端口都在规则定义的范围内则返回1，否则返回0
 */
always_inline int
match_portranges(acl_main_t *am, fa_5tuple_t *match, u32 index)
{

  // 获取应用的哈希ACL条目数组
  applied_hash_ace_entry_t **applied_hash_aces = vec_elt_at_index(am->hash_entry_vec_by_lc_index, match->pkt.lc_index);
  // 从数组中获取特定索引的哈希ACL条目
  applied_hash_ace_entry_t *pae = vec_elt_at_index((*applied_hash_aces), index);

  // 获取对应的ACL规则
  acl_rule_t *r = &(am->acls[pae->acl_index].rules[pae->ace_index]);

#ifdef FA_NODE_VERBOSE_DEBUG
  // 输出调试信息，显示规则的端口范围和数据包的实际端口号
  clib_warning("PORTMATCH: %d <= %d <= %d && %d <= %d <= %d ?",
		r->src_port_or_type_first, match->l4.port[0], r->src_port_or_type_last,
		r->dst_port_or_code_first, match->l4.port[1], r->dst_port_or_code_last);
#endif

  // 检查数据包的端口是否在规则定义的范围内
  return ( ((r->src_port_or_type_first <= match->l4.port[0]) && r->src_port_or_type_last >= match->l4.port[0]) &&
           ((r->dst_port_or_code_first <= match->l4.port[1]) && r->dst_port_or_code_last >= match->l4.port[1]) );
}

/**
 * @brief Check if a single ACL rule matches a 5-tuple
 *
 * 此内联函数用于基于五元组信息和单个ACL规则，判断数据包是否匹配规则。它首先检查IP版本是否匹配，然后根据IP版本分别检查IP地址、端口和TCP标志是否符合规则。
 *
 * @param r 指向ACL规则结构的指针
 * @param is_ip6 是否为IPv6数据包的标志
 * @param pkt_5tuple 指向FA五元组结构的指针
 * @return 返回匹配结果，1表示匹配，0表示不匹配
 */

always_inline int
single_rule_match_5tuple (acl_rule_t * r, int is_ip6, fa_5tuple_t * pkt_5tuple)
{
  if (is_ip6 != r->is_ipv6)
    {
      return 0;
    }

  if (is_ip6)
    {
      if (!fa_acl_match_ip6_addr
	  (&pkt_5tuple->ip6_addr[1], &r->dst.ip6, r->dst_prefixlen))
	return 0;
      if (!fa_acl_match_ip6_addr
	  (&pkt_5tuple->ip6_addr[0], &r->src.ip6, r->src_prefixlen))
	return 0;
    }
  else
    {
      if (!fa_acl_match_ip4_addr
	  (&pkt_5tuple->ip4_addr[1], &r->dst.ip4, r->dst_prefixlen))
	return 0;
      if (!fa_acl_match_ip4_addr
	  (&pkt_5tuple->ip4_addr[0], &r->src.ip4, r->src_prefixlen))
	return 0;
    }

  if (r->proto)
    {
      if (pkt_5tuple->l4.proto != r->proto)
	return 0;

      /* A sanity check just to ensure we are about to match the ports extracted from the packet */
      if (PREDICT_FALSE (!pkt_5tuple->pkt.l4_valid))
	return 0;


      if (!fa_acl_match_port
	  (pkt_5tuple->l4.port[0], r->src_port_or_type_first,
	   r->src_port_or_type_last, pkt_5tuple->pkt.is_ip6))
	return 0;


      if (!fa_acl_match_port
	  (pkt_5tuple->l4.port[1], r->dst_port_or_code_first,
	   r->dst_port_or_code_last, pkt_5tuple->pkt.is_ip6))
	return 0;

      if (pkt_5tuple->pkt.tcp_flags_valid
	  && ((pkt_5tuple->pkt.tcp_flags & r->tcp_flags_mask) !=
	      r->tcp_flags_value))
	return 0;
    }
  /* everything matches! */
  return 1;
}

/**
 * @brief Get index of the applied ACE entry via hash lookup
 *
 * 此内联函数用于基于五元组信息和哈希表，获取匹配的ACE（Access Control Entry）条目索引。它通过哈希表查找和碰撞处理来确定最合适的ACE条目。
 *
 * @param am 指向ACL主控结构的指针
 * @param is_ip6 是否为IPv6数据包的标志
 * @param match 指向FA五元组结构的指针
 * @return 返回匹配的ACE条目索引
 */
always_inline u32
multi_acl_match_get_applied_ace_index (acl_main_t * am, int is_ip6, fa_5tuple_t * match)
{
  // 声明一个哈希表键值对结构体
  clib_bihash_kv_48_8_t kv;
  // 声明一个存储结果的哈希表键值对结构体
  clib_bihash_kv_48_8_t result;
  // 将kv.key转换为fa_5tuple_t类型指针
  fa_5tuple_t *kv_key = (fa_5tuple_t *) kv.key;
  // 将result.value转换为hash_acl_lookup_value_t类型指针
  hash_acl_lookup_value_t *result_val =
    (hash_acl_lookup_value_t *) & result.value;
  // 将match转换为64位无符号整数指针
  u64 *pmatch = (u64 *) match;
  u64 *pmask;
  u64 *pkey;
  int mask_type_index, order_index;
  // 当前匹配的索引，初始值为最大值减1
  u32 curr_match_index = (~0 - 1);



  // 获取匹配项中的lc_index
  u32 lc_index = match->pkt.lc_index;
  // 获取当前lc_index对应的applied_hash_ace_entry_t向量
  applied_hash_ace_entry_t **applied_hash_aces =
    vec_elt_at_index (am->hash_entry_vec_by_lc_index, lc_index);

  // 获取当前lc_index对应的hash_applied_mask_info_t向量
  hash_applied_mask_info_t **hash_applied_mask_info_vec =
    vec_elt_at_index (am->hash_applied_mask_info_vec_by_lc_index, lc_index);

  hash_applied_mask_info_t *minfo;

  DBG ("TRYING TO MATCH: %016llx %016llx %016llx %016llx %016llx %016llx",
       pmatch[0], pmatch[1], pmatch[2], pmatch[3], pmatch[4], pmatch[5]);

  // 遍历掩码信息向量
  for (order_index = 0; order_index < vec_len ((*hash_applied_mask_info_vec));
       order_index++)
    {
      minfo = vec_elt_at_index ((*hash_applied_mask_info_vec), order_index);
      if (minfo->first_rule_index > curr_match_index)
	{
	  /* Index in this and following (by construction) partitions are greater than our candidate, Avoid trying to match! */
    // 如果当前掩码的第一个规则索引大于当前匹配索引，则跳出循环
	  break;
	}

      // 获取掩码类型索引
      mask_type_index = minfo->mask_type_index;
      // 获取掩码类型条目
      ace_mask_type_entry_t *mte =
	vec_elt_at_index (am->ace_mask_type_pool, mask_type_index);
      // 重置pmatch指针
      pmatch = (u64 *) match;
      // 将掩码转换为64位无符号整数指针
      pmask = (u64 *) & mte->mask;
      // 将键转换为64位无符号整数指针
      pkey = (u64 *) kv.key;
      /*
       * unrolling the below loop results in a noticeable performance increase.
       int i;
       for(i=0; i<6; i++) {
       kv.key[i] = pmatch[i] & pmask[i];
       }
       */
      // 使用掩码对匹配项进行掩码处理，并赋值给键
      *pkey++ = *pmatch++ & *pmask++;
      *pkey++ = *pmatch++ & *pmask++;
      *pkey++ = *pmatch++ & *pmask++;
      *pkey++ = *pmatch++ & *pmask++;
      *pkey++ = *pmatch++ & *pmask++;
      *pkey++ = *pmatch++ & *pmask++;

      /*
       * The use of temporary variable convinces the compiler
       * to make a u64 write, avoiding the stall on crc32 operation
       * just a bit later.
       */
      // 使用临时变量避免在后续操作中出现写入延迟
      fa_packet_info_t tmp_pkt = kv_key->pkt;
      tmp_pkt.mask_type_index_lsb = mask_type_index;
      kv_key->pkt.as_u64 = tmp_pkt.as_u64;
      // 在哈希表中搜索键值对
      int res =
	clib_bihash_search_inline_2_48_8 (&am->acl_lookup_hash, &kv, &result);

      if (res == 0)
	{
	  /* There is a hit in the hash, so check the collision vector */
	  // 如果在哈希表中找到匹配项，则检查碰撞向量
    u32 curr_index = result_val->applied_entry_index;
	  applied_hash_ace_entry_t *pae =
	    vec_elt_at_index ((*applied_hash_aces), curr_index);
	  collision_match_rule_t *crs = pae->colliding_rules;
	  int i;
	  for (i = 0; i < vec_len (crs); i++)
	    {
	      if (crs[i].applied_entry_index >= curr_match_index)
		{
      // 如果碰撞规则索引大于等于当前匹配索引，则继续
		  continue;
		}
	      if (single_rule_match_5tuple (&crs[i].rule, is_ip6, match))
		{
      // 如果单条规则匹配，则更新当前匹配索引
		  curr_match_index = crs[i].applied_entry_index;
		}
	    }
	}
    }
  DBG ("MATCH-RESULT: %d", curr_match_index);
  // 返回当前匹配索引
  return curr_match_index;
}

/**
 * @brief Perform hash match of 5-tuple against multiple ACLs
 *
 * 此内联函数用于基于五元组信息通过哈希匹配的方式匹配多个ACL。它利用预先构建的哈希表来加速ACL匹配过程。
 *
 * @param p_acl_main 指向ACL主控结构的指针
 * @param lc_index 逻辑链索引
 * @param pkt_5tuple 指向FA五元组结构的指针
 * @param is_ip6 是否为IPv6数据包的标志
 * @param action 指向u8类型的指针，用于存储匹配结果的动作
 * @param acl_pos_p 指向u32类型的指针，用于存储匹配结果的ACL位置
 * @param acl_match_p 指向u32类型的指针，用于存储匹配结果的ACL匹配索引
 * @param rule_match_p 指向u32类型的指针，用于存储匹配结果的规则匹配索引
 * @param trace_bitmap 指向u32类型的指针，用于存储跟踪位图
 * @return 返回匹配结果，1表示匹配成功，0表示未匹配
 */
always_inline int
hash_multi_acl_match_5tuple (void *p_acl_main, u32 lc_index, fa_5tuple_t * pkt_5tuple,
                       int is_ip6, u8 *action, u32 *acl_pos_p, u32 * acl_match_p,
                       u32 * rule_match_p, u32 * trace_bitmap)
{
  acl_main_t *am = p_acl_main;
  applied_hash_ace_entry_t **applied_hash_aces = vec_elt_at_index(am->hash_entry_vec_by_lc_index, lc_index);
  //基于五元组信息和IPv6标志获取匹配的ACE条目索引
  u32 match_index = multi_acl_match_get_applied_ace_index(am, is_ip6, pkt_5tuple);
  //如果匹配索引在ACE条目数组的有效范围内，表示找到了匹配项
  if (match_index < vec_len((*applied_hash_aces))) {
    //更新找到的ACE条目的命中计数，
    //并将ACL位置、ACL匹配索引、规则匹配索引和动作分别存储到相应的输出参数中，
    //最后返回1表示匹配成功
    applied_hash_ace_entry_t *pae = vec_elt_at_index((*applied_hash_aces), match_index);
    pae->hitcount++;
    *acl_pos_p = pae->acl_position;
    *acl_match_p = pae->acl_index;
    *rule_match_p = pae->ace_index;
    *action = pae->action;
    return 1;
  }
  return 0;
}



/**
 * @brief Match 5-tuple against ACLs using hash or linear matching
 *
 * 此内联函数用于根据五元组信息，在ACL插件中匹配访问控制列表。它可以选择使用哈希匹配或线性匹配方法，具体取决于配置和数据包是否为非首片分片。
 *
 * @param p_acl_main 指向ACL主控结构的指针
 * @param lc_index 逻辑链索引
 * @param pkt_5tuple 指向FA五元组不透明类型的指针
 * @param is_ip6 是否为IPv6数据包的标志
 * @param r_action 指向u8类型的指针，用于存储匹配结果的动作
 * @param r_acl_pos_p 指向u32类型的指针，用于存储匹配结果的ACL位置
 * @param r_acl_match_p 指向u32类型的指针，用于存储匹配结果的ACL匹配索引
 * @param r_rule_match_p 指向u32类型的指针，用于存储匹配结果的规则匹配索引
 * @param trace_bitmap 指向u32类型的指针，用于存储跟踪位图
 * @return 返回匹配结果，通常为零或非零值
 */
always_inline int
acl_plugin_match_5tuple_inline (void *p_acl_main, u32 lc_index,
                                           fa_5tuple_opaque_t * pkt_5tuple,
                                           int is_ip6, u8 * r_action,
                                           u32 * r_acl_pos_p,
                                           u32 * r_acl_match_p,
                                           u32 * r_rule_match_p,
                                           u32 * trace_bitmap)
{
  acl_main_t *am = p_acl_main;
  fa_5tuple_t * pkt_5tuple_internal = (fa_5tuple_t *)pkt_5tuple;
  pkt_5tuple_internal->pkt.lc_index = lc_index;
  //使用哈希匹配还是线性匹配
  if (PREDICT_TRUE(am->use_hash_acl_matching)) {
    //如果数据包是非首片分片，由于哈希匹配不考虑分片，函数将回退到线性匹配方法
    if (PREDICT_FALSE(pkt_5tuple_internal->pkt.is_nonfirst_fragment)) {
      /*
       * tuplemerge does not take fragments into account,
       * and in general making fragments first class citizens has
       * proved more overhead than it's worth - so just fall back to linear
       * matching in that case.
       */
      return linear_multi_acl_match_5tuple(p_acl_main, lc_index, pkt_5tuple_internal, is_ip6, r_action,
                                 r_acl_pos_p, r_acl_match_p, r_rule_match_p, trace_bitmap);
    } else {
      return hash_multi_acl_match_5tuple(p_acl_main, lc_index, pkt_5tuple_internal, is_ip6, r_action,
                                 r_acl_pos_p, r_acl_match_p, r_rule_match_p, trace_bitmap);
    }
  } else {
    return linear_multi_acl_match_5tuple(p_acl_main, lc_index, pkt_5tuple_internal, is_ip6, r_action,
                                 r_acl_pos_p, r_acl_match_p, r_rule_match_p, trace_bitmap);
  }
}


always_inline int
acl_plugin_match_5tuple_inline_and_count (void *p_acl_main, u32 lc_index,
                                           fa_5tuple_opaque_t * pkt_5tuple,
                                           int is_ip6, u8 * r_action,
                                           u32 * r_acl_pos_p,
                                           u32 * r_acl_match_p,
                                           u32 * r_rule_match_p,
                                           u32 * trace_bitmap,
					   u32 packet_size)
{
  acl_main_t *am = p_acl_main;
  int ret = 0;
  fa_5tuple_t * pkt_5tuple_internal = (fa_5tuple_t *)pkt_5tuple;
  pkt_5tuple_internal->pkt.lc_index = lc_index;
  if (PREDICT_TRUE(am->use_hash_acl_matching)) {
    if (PREDICT_FALSE(pkt_5tuple_internal->pkt.is_nonfirst_fragment)) {
      /*
       * tuplemerge does not take fragments into account,
       * and in general making fragments first class citizens has
       * proved more overhead than it's worth - so just fall back to linear
       * matching in that case.
       */
      ret = linear_multi_acl_match_5tuple(p_acl_main, lc_index, pkt_5tuple_internal, is_ip6, r_action,
                                 r_acl_pos_p, r_acl_match_p, r_rule_match_p, trace_bitmap);
    } else {
      ret = hash_multi_acl_match_5tuple(p_acl_main, lc_index, pkt_5tuple_internal, is_ip6, r_action,
                                 r_acl_pos_p, r_acl_match_p, r_rule_match_p, trace_bitmap);
    }
  } else {
    ret = linear_multi_acl_match_5tuple(p_acl_main, lc_index, pkt_5tuple_internal, is_ip6, r_action,
                                 r_acl_pos_p, r_acl_match_p, r_rule_match_p, trace_bitmap);
  }
  if (PREDICT_TRUE(ret)) {
	  u16 thread_index = os_get_thread_index ();
	  vlib_increment_combined_counter(am->combined_acl_counters + *r_acl_match_p, thread_index, *r_rule_match_p, 1, packet_size);
  }
  return ret;
}




#endif
