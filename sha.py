from utilidades import *

def binario(msg):
    chars = [ord(c) for c in msg] #devuelve un arreglo de los codigos unicode de cada caracter
    bytes = []
    for char in chars:
        bytes.append(bin(char)[2:].zfill(8)) #convierte a bytes y agrega a aun arreglo, eliminando indicador binario
    bits = []
    for byte in bytes:
        for bit in byte:
            bits.append(int(bit)) #guarda los bytes en un arreglo de bits
    return bits

def binahex(msg):
    msg = ''.join([str(x) for x in msg]) #convierte cada bit a string
    binarios = []
    for d in range(0, len(msg), 4):
        binarios.append('0b' + msg[d:d + 4]) #guarda conjuntos de 4 bits binarios como strings
    hexes = '' #crea un string vacio para agregar los valores hexadecimales
    for b in binarios:
        hexes += hex(int(b, 2))[2:] #elimina el indicador de string hexadecimal y concatena
    return hexes


def ceros(bits, long=8, endian="L"): #agrega ceros al mensaje para llegar a la longitud deseada
    l = len(bits)
    if endian == "L": #define si se usa little endian o big endian para posicionar los ceros
        for i in range(l, long):
            bits.append(0)
    else:
        while l < long:
            bits.insert(0, 0)
            l = len(bits)
    return bits

def cortador(bits, porcion = 8): #recorta el mensaje en porciones para procesarlas individualmente
    cortado = []
    for i in range (0, len(bits), porcion):
        cortado.append(bits[i:i+porcion])
    return cortado

#hashes iniciales y constantes obtenidos del Instituto Nacional de Estandares y Tecnologia de EE.UU
H = ["0x6a09e667", "0xbb67ae85", "0x3c6ef372", "0xa54ff53a", "0x510e527f", "0x9b05688c", "0x1f83d9ab", "0x5be0cd19"]

K = ["0x428a2f98", "0x71374491", "0xb5c0fbcf", "0xe9b5dba5", "0x3956c25b", "0x59f111f1", "0x923f82a4","0xab1c5ed5", "0xd807aa98", "0x12835b01", "0x243185be", "0x550c7dc3", "0x72be5d74", "0x80deb1fe","0x9bdc06a7", "0xc19bf174", "0xe49b69c1", "0xefbe4786", "0x0fc19dc6", "0x240ca1cc", "0x2de92c6f","0x4a7484aa", "0x5cb0a9dc", "0x76f988da", "0x983e5152", "0xa831c66d", "0xb00327c8", "0xbf597fc7","0xc6e00bf3", "0xd5a79147", "0x06ca6351", "0x14292967", "0x27b70a85", "0x2e1b2138", "0x4d2c6dfc","0x53380d13", "0x650a7354", "0x766a0abb", "0x81c2c92e", "0x92722c85", "0xa2bfe8a1", "0xa81a664b","0xc24b8b70", "0xc76c51a3", "0xd192e819", "0xd6990624", "0xf40e3585", "0x106aa070", "0x19a4c116","0x1e376c08", "0x2748774c", "0x34b0bcb5", "0x391c0cb3", "0x4ed8aa4a", "0x5b9cca4f", "0x682e6ff3","0x748f82ee", "0x78a5636f", "0x84c87814", "0x8cc70208", "0x90befffa", "0xa4506ceb", "0xbef9a3f7","0xc67178f2"]

def inicializar(val):
    binarios = [bin(int(v, 16))[2:] for v in val] # convierte a binario sin indicador
    lista = []
    for binario in binarios:
        palabra = []
        for b in binario:
            palabra.append(int(b))
        lista.append(ceros(palabra, 32, "BE"))
    return lista

def preprocesar(msg): # prepara el mensaje para la funcion principal del algoritmo
    bits = binario(msg)
    long = len(bits)
    msj_long = [int(b) for b in bin(long)[2:].zfill(64)]
    if long < 448:
        bits.append(1)
        bits = ceros(bits, 448, 'L')
        bits = bits + msj_long
        return [bits]
    elif 448 <= long <= 512:
        bits.append(1)
        bits = ceros(bits, 1024, 'L')
        bits[-64:] = msj_long
        return cortador(bits, 512)
    else:
        bits.append(1)
        while (len(bits) + 64) % 512 != 0:
            bits.append(0)
        bits = bits + msj_long
        return cortador(bits, 512)


def sha256(msg): # procesa el mensaje, procedimiento principal para generar el hash.
    k = inicializar(K)
    h0, h1, h2, h3, h4, h5, h6, h7 = inicializar(H)
    pedazos = preprocesar(msg)
    for pedazo in pedazos:
        w = cortador(pedazo, 32)
        for _ in range(48):
            w.append(32 * [0])
        for i in range(16, 64):
            s0 = XORXOR(rotr(w[i-15], 7), rotr(w[i-15], 18), shr(w[i-15], 3) )
            s1 = XORXOR(rotr(w[i-2], 17), rotr(w[i-2], 19), shr(w[i-2], 10))
            w[i] = add(add(add(w[i-16], s0), w[i-7]), s1)
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4
        f = h5
        g = h6
        h = h7
        for j in range(64):
            S1 = XORXOR(rotr(e, 6), rotr(e, 11), rotr(e, 25) )
            ch = XOR(AND(e, f), AND(NOT(e), g))
            temp1 = add(add(add(add(h, S1), ch), k[j]), w[j])
            S0 = XORXOR(rotr(a, 2), rotr(a, 13), rotr(a, 22))
            m = XORXOR(AND(a, b), AND(a, c), AND(b, c))
            temp2 = add(S0, m)
            h = g
            g = f
            f = e
            e = add(d, temp1)
            d = c
            c = b
            b = a
            a = add(temp1, temp2)
        h0 = add(h0, a)
        h1 = add(h1, b)
        h2 = add(h2, c)
        h3 = add(h3, d)
        h4 = add(h4, e)
        h5 = add(h5, f)
        h6 = add(h6, g)
        h7 = add(h7, h)
    digest = ''
    for val in [h0, h1, h2, h3, h4, h5, h6, h7]:
        digest += binahex(val)
    return digest
