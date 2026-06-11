#include <stdint.h>
#include <string.h>
#include <stdio.h>

//Constantes SHA256 (primeiros 32 bits das raízes cúbicas dos primeiros 64 primos)
static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

//Rotação circular direita
static uint32_t rotr(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

//funções logicas do SHA-256
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22))
#define EP1(x) (rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25))
#define SIG0(x) (rotr(x, 7) ^ rotr(x, 18) ^ ((x) >> 3))
#define SIG1(x) (rotr(x, 17) ^ rotr(x, 19) ^ ((x) >> 10))

//Estrutura do contexto SHA-256
typedef struct {
    uint32_t estado[8];     //hash intermediário
    uint8_t buffer[64];     //buffer de dados
    uint64_t contador;      //contador de bits
} SHA256_CTX;

//função de compressão do SHA-256
static void sha256_transform(SHA256_CTX *ctx) {
    uint32_t W[64];
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t T1, T2;
    int i;
    
    //prepara o vetor W (48 primeiros são do buffer, os restantes calculados)
    for (i = 0; i < 16; i++) {
        W[i] = (ctx->buffer[i*4] << 24) | (ctx->buffer[i*4+1] << 16) | 
               (ctx->buffer[i*4+2] << 8) | (ctx->buffer[i*4+3]);
    }
    
    for (i = 16; i < 64; i++) {
        W[i] = SIG1(W[i-2]) + W[i-7] + SIG0(W[i-15]) + W[i-16];
    }
    
    //inicializa variáveis de trabalho
    a = ctx->estado[0];
    b = ctx->estado[1];
    c = ctx->estado[2];
    d = ctx->estado[3];
    e = ctx->estado[4];
    f = ctx->estado[5];
    g = ctx->estado[6];
    h = ctx->estado[7];
    
    //Loop principal
    for (i = 0; i < 64; i++) {
        T1 = h + EP1(e) + CH(e, f, g) + K[i] + W[i];
        T2 = EP0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }
    
    //atualiza o estado
    ctx->estado[0] += a;
    ctx->estado[1] += b;
    ctx->estado[2] += c;
    ctx->estado[3] += d;
    ctx->estado[4] += e;
    ctx->estado[5] += f;
    ctx->estado[6] += g;
    ctx->estado[7] += h;
}

//inicializa o contexto SHA-256 (valores iniciais do hash)
void sha256_init(SHA256_CTX *ctx) {
    ctx->estado[0] = 0x6a09e667;
    ctx->estado[1] = 0xbb67ae85;
    ctx->estado[2] = 0x3c6ef372;
    ctx->estado[3] = 0xa54ff53a;
    ctx->estado[4] = 0x510e527f;
    ctx->estado[5] = 0x9b05688c;
    ctx->estado[6] = 0x1f83d9ab;
    ctx->estado[7] = 0x5be0cd19;
    ctx->contador = 0;
    memset(ctx->buffer, 0, 64);
}

//atualiza o hash com novos dados
void sha256_update(SHA256_CTX *ctx, const uint8_t *dados, size_t tamanho) {
    size_t i;
    size_t espaco;
    
    for (i = 0; i < tamanho; i++) {
        espaco = (size_t)((ctx->contador / 8) % 64);
        ctx->buffer[espaco] = dados[i];
        ctx->contador += 8; // 8 bits
        
        if (espaco == 63) {
            sha256_transform(ctx);
            memset(ctx->buffer, 0, 64);
        }
    }
}

//finaliza o hash e retorna o resultado
void sha256_final(SHA256_CTX *ctx, uint8_t *saida) {
    uint64_t contador_bits = ctx->contador;
    size_t espaco = (size_t)((ctx->contador / 8) % 64);
    int i;
    
    //padding: adiciona 0x80
    sha256_update(ctx, (const uint8_t*)"\x80", 1);
    
    //se não tem espaço para o tamanho (8 bytes), adiciona mais um bloco
    if (espaco >= 56) {
        //preenche com zeros até o final do bloco
        while ((ctx->contador / 8) % 64 != 0) {
            sha256_update(ctx, (const uint8_t*)"\x00", 1);
        }
    }
    
    //Adiciona o padding com zeros até ter espaço para o tamanho
    while ((ctx->contador / 8) % 64 != 56) {
        sha256_update(ctx, (const uint8_t*)"\x00", 1);
    }
    
    //adiciona o tamanho em bits (big-endian)
    for (i = 7; i >= 0; i--) {
        uint8_t byte = (contador_bits >> (i * 8)) & 0xFF;
        sha256_update(ctx, &byte, 1);
    }
    
    //converte o estado para bytes (big-endian)
    for (i = 0; i < 8; i++) {
        saida[i*4]   = (ctx->estado[i] >> 24) & 0xFF;
        saida[i*4+1] = (ctx->estado[i] >> 16) & 0xFF;
        saida[i*4+2] = (ctx->estado[i] >> 8) & 0xFF;
        saida[i*4+3] = ctx->estado[i] & 0xFF;
    }
}

//função principal SHA 256 (interface simplificada)
void sha256(const uint8_t *mensagem, size_t tamanho, uint8_t *saida) {
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, mensagem, tamanho);
    sha256_final(&ctx, saida);
}


int main() {
    uint8_t hash[32];
    const char *teste = "Oi eu sou o Vitor";
    
    sha256((const uint8_t*)teste, strlen(teste), hash);
    
    printf("SHA256 de '%s':\n", teste);
    for (int i = 0; i < 32; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
    
    return 0;
}