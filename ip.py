from ipaddress import ip_address, ip_network
from iputils import *
import struct


class IP:
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        self.identification = 0

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            next_hop = self._next_hop(dst_addr)
            # TODO: Trate corretamente o campo TTL do datagrama
            #Passo 4
            --ttl #decrementando TTL
            if ttl !=0:
                header = self._header(payload, dst_addr, src_addr,
                                      dscp=dscp, ecn=ecn, identification=identification,
                                      flags=flags, frag_offset=frag_offset, ttl=ttl, protocol=proto)
                datagrama = header + payload
                self.enlace.enviar(datagrama, next_hop)
            elif ttl == 0:
                next_hop = self._next_hop(src_addr)
                self.enlace.enviar(next_hop, next_hop)


    def _next_hop(self, dest_addr):
        # TODO: Use a tabela de encaminhamento para determinar o próximo salto
        # (next_hop) a partir do endereço de destino do datagrama (dest_addr).
        # Retorne o next_hop para o dest_addr fornecido.
        enc = []
        for itemTabela in self.tabela:
            if ip_address(dest_addr) in ip_network(itemTabela[0]):
                enc = [itemTabela]
        enc.sort(key = lambda x: ip_network(x[0]).prefixlen, reverse = True)
        if enc:
            return enc[0][1]
        
        if len(enc) > 0:
            enc.sort(key=lambda x: x[0], reverse=True)
            cidr = enc[0][1]
            return self.tabela[cidr]


    def _header(self, seg, dest_addr, source_addr=None, version=4, ihl=5,
                      dscp=0, ecn=0, identification=None, flags=0, frag_offset=0, 
                      ttl=64, protocol=IPPROTO_TCP, header_checksum=0):
        len_total = len(seg) + 20
        if identification is None:
            identification = self.identification
            ++self.identification
        elif source_addr is None:
            source_addr = self.meu_endereco

        vihl = (version << 4) | ihl  
        dscpecn = (dscp << 2) | ecn 
        flagsfrag = (flags << 13) | frag_offset 
        
        source_addr = struct.unpack('!I', source_addr)
        source_addr = struct.unpack('!I', dest_addr)
        temp = struct.pack('!BBHHHBBHII', vihl, dscpecn, len_total,
                           identification, flagsfrag, ttl, protocol, header_checksum,
                           source_addr, dest_addr)
        header_checksum = calc_checksum(temp)
        header = struct.pack('!BBHHHBBHII', vihl, dscpecn, len_total,
                             identification, flagsfrag, ttl, protocol, header_checksum,
                             source_addr, dest_addr)
        return header

    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]

        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        # TODO: Guarde a tabela de encaminhamento. Se julgar conveniente,
        # converta-a em uma estrutura de dados mais eficiente.
        #passo 1
        self.tabela = tabela

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        next_hop = self._next_hop(dest_addr)
        # TODO: Assumindo que a camada superior é o protocolo TCP, monte o
        # datagrama com o cabeçalho IP, contendo como payload o segmento.
        self.enlace.enviar(datagrama, next_hop)
