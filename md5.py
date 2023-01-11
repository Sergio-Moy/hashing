# Algoritmo de Resumen de Mensaje 5 (MD5)

import math


def reordenar(Cad32bits):
    if len(Cad32bits) != 32:
        raise ValueError("Necesita una longitud de 32")
    NuevaCadena = ""
    for i in [3, 2, 1, 0]:
        NuevaCadena += Cad32bits[8 * i:8 * i + 8]
    return NuevaCadena


def ConvertirHex(i):
    hexadecimalRep = format(i, '08x')  # convierte el input a númera hexadecimal
    aux = ""
    for i in [3, 2, 1, 0]:
        aux += hexadecimalRep[2 * i:2 * i + 2]  # re-ordena el número hexadecimal obtenido
    return aux


def pad(mensajeBits):
    tamanoInicial = len(mensajeBits)
    mensajeBits += '1'  # un sólo bit "1" se añade al mensaje
    while len(
            mensajeBits) % 512 != 448:  # El mensaje será extendido hasta que su longitud en bits sea congruente con 448, módulo 512
        mensajeBits += '0'  # bits "0" se añaden hasta que la longitud en bits del mensaje es congruente con 448, módulo 512
    tamano64bits = format(tamanoInicial, '064b')  # convierte a 64 bits
    mensajeBits += reordenar(tamano64bits[32:]) + reordenar(
        tamano64bits[:32])  # re-ordena la longitud del mensaje (representada en 64 bits)
    return mensajeBits


def obtenerBloque(mensajeBits):
    posActual = 0
    while posActual < len(mensajeBits):
        parteActual = mensajeBits[posActual:posActual + 512]  # va recorriendo todos los segmentos de 512 bits
        mySplits = []
        for i in range(16):  # separa la parte actual en segmentos de 16 bits
            mySplits.append(int(reordenar(parteActual[32 * i:32 * i + 32]),
                                2))  # agrega el segmento actual re-ordenado en código binario a la lista
        yield mySplits  # retorna la lista sin perder el estado actual de esta
        posActual += 512  # para poder pasar al siguiente segmento del mensaje en bits


def not32(i):
    i_str = format(i, '032b')
    new_str = ''
    for c in i_str:
        new_str += '1' if c == '0' else '0'
    return int(new_str, 2)


def sum32(a, b):
    return (a + b) % 2 ** 32


def leftrot32(i, s):
    return (i << s) ^ (i >> (32 - s))


def md5me(testString):
    bs = ''
    for i in testString:
        bs += format(ord(i),
                     '08b')  # convierte cada caracter del mensaje que queremos codificar a 8 bits (se pasa todo a 0 y 1)
    bs = pad(bs)

    tvals = [int(2 ** 32 * abs(math.sin(i + 1))) for i in range(64)]

    a0 = 0x67452301
    b0 = 0xefcdab89
    c0 = 0x98badcfe
    d0 = 0x10325476

    s = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
         5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
         4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
         6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21]

    for m in obtenerBloque(bs):
        A = a0
        B = b0
        C = c0
        D = d0
        for i in range(64):  # verifica la longitud/valor del bloque obtenido (obtenerBloque)
            if i <= 15:
                # f = (B & C) | (not32(B) & D)
                f = D ^ (B & (C ^ D))
                g = i
            elif i <= 31:
                # f = (D & B) | (not32(D) & C)
                f = C ^ (D & (B ^ C))
                g = (5 * i + 1) % 16
            elif i <= 47:
                f = B ^ C ^ D
                g = (3 * i + 5) % 16
            else:
                f = C ^ (B | not32(D))
                g = (7 * i) % 16
            dtemp = D
            D = C
            C = B
            B = sum32(B, leftrot32((A + f + tvals[i] + m[g]) % 2 ** 32, s[i]))
            A = dtemp
        a0 = sum32(a0, A)
        b0 = sum32(b0, B)
        c0 = sum32(c0, C)
        d0 = sum32(d0, D)

    digest = ConvertirHex(a0) + ConvertirHex(b0) + ConvertirHex(c0) + ConvertirHex(d0)
    return digest
