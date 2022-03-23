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
            # roteador
            next_hop = self._next_hop(dst_addr)
            # TODO: Trate corretamente o campo TTL do datagrama
            #Passo 4
            vihl, dscpecn, total_len, identification, flagsfrag, ttl, proto, \
            checksum, src_addr, dest_addr = \
            struct.unpack('!BBHHHBBHII', datagrama[:20])
            #decrementa ttl
            --ttl

            if ttl == 0:
                typ = 11
                code = 0
                checksum_icmp = calc_checksum(struct.pack('!BBHI', typ,code,0,0)+datagrama[:28])
                icmp = struct.pack('!BBHI', typ,code,checksum_icmp,0) + datagrama[:28]
                next_hop = self._next_hop(src_addr)
                addr_int = int.from_bytes(str2addr(self.meu_endereco), "big")
                checksum = calc_checksum(struct.pack('!BBHHHBBHII', vihl, dscpecn, 20+len(icmp), identification, flagsfrag, 64, 1, 0, addr_int, src_addr))
                datagrama = struct.pack('!BBHHHBBHII', vihl, dscpecn, 20+len(icmp), identification, flagsfrag, 64, 1, checksum, addr_int, src_addr) + icmp
                self.idn+=1
                self.enlace.enviar(datagrama, next_hop)
            else:
                checksum = calc_checksum(struct.pack('!BBHHHBBHII', vihl, dscpecn, total_len, identification, flagsfrag, ttl, proto, 0, src_addr, dest_addr))
                datagrama = struct.pack('!BBHHHBBHII', vihl, dscpecn, total_len, identification, flagsfrag, ttl, proto, checksum, src_addr, dest_addr) + datagrama[20:]
                self.enlace.enviar(datagrama, next_hop)

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
